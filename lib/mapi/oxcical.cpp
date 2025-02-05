// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2022–2024 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <fmt/format.h>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/ical.hpp>
#include <gromox/mapidefs.h>
#include <gromox/oxcmail.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#define MAX_TZRULE_NUMBER						128

#define MAX_TZDEFINITION_LENGTH					(68*MAX_TZRULE_NUMBER+270)

using namespace std::string_literals;
using namespace gromox;
using propididmap_t = std::unordered_map<uint16_t, uint16_t>;
using namemap = std::unordered_map<int, PROPERTY_NAME>;
using event_list_t = std::vector<const ical_component *>;
using uidxevent_list_t = std::unordered_map<std::string, event_list_t>;
using message_ptr = std::unique_ptr<MESSAGE_CONTENT, mc_delete>;

namespace gromox {
bool g_oxcical_allday_ymd = true; /* MS-OXCICAL v13 §2.1.3.1.1.20.8 p. 49. */
bool oxcmail_exchsched_compat = false;
}

static constexpr char
	PidNameKeywords[] = "Keywords",
	PidNameLocationUrl[] = "urn:schemas:calendar:locationurl";
static constexpr size_t namemap_limit = 0x1000;
static constexpr uint32_t indet_rendering_pos = UINT32_MAX;
static constexpr char fmt_date[] = "%04d%02d%02d",
	fmt_datetimelcl[] = "%04d%02d%02dT%02d%02d%02d",  /* needs buf[16] */
	fmt_datetimeutc[] = "%04d%02d%02dT%02d%02d%02dZ"; /* needs buf[17] */

static int namemap_add(namemap &phash, uint32_t id, PROPERTY_NAME &&el) try
{
	/* Avoid uninitialized read when the copy/transfer is made */
	if (el.kind == MNID_ID)
		el.pname = nullptr;
	else
		el.lid = 0;
	if (phash.size() >= namemap_limit)
		return -ENOSPC;
	if (!phash.emplace(id, std::move(el)).second)
		return -EEXIST;
	return 0;
} catch (const std::bad_alloc &) {
	return -ENOMEM;
}

static bool oxcical_parse_vtsubcomponent(const ical_component &sub,
	int32_t *pbias, int32_t *pdaylightbias, int16_t *pyear,
	SYSTEMTIME *pdate)
{
	int hour;
	int minute;
	int dayofweek;
	int weekorder;
	const char *pvalue;
	const char *pvalue1;
	const char *pvalue2;

	memset(pdate, 0, sizeof(SYSTEMTIME));
	auto piline = sub.get_line("TZOFFSETTO");
	if (piline == nullptr)
		return false;
	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return false;
	if (!ical_parse_utc_offset(pvalue, &hour, &minute))
		return false;
	*pbias = 60*hour + minute;
	if (strcasecmp(sub.m_name.c_str(), "DAYLIGHT") == 0) {
		piline = sub.get_line("TZOFFSETFROM");
		if (piline == nullptr)
			return false;
		pvalue = piline->get_first_subvalue();
		if (pvalue == nullptr)
			return false;
		int fromhour, fromminute;
		if (!ical_parse_utc_offset(pvalue, &fromhour, &fromminute))
			return false;
		*pdaylightbias = 60 * hour + minute - (60 * fromhour + fromminute);
	}
	piline = sub.get_line("DTSTART");
	if (piline == nullptr)
		return false;
	if (piline->get_first_paramval("TZID") != nullptr)
		return false;
	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return false;
	ical_time itime{};
	if (!ical_parse_datetime(pvalue, &itime) || itime.type == ICT_UTC)
		/* Z specifier should not be used with VTIMEZONE.DTSTART */
		return false;
	*pyear = itime.year;
	pdate->hour = itime.hour;
	pdate->minute = itime.minute;
	pdate->second = itime.second;
	piline = sub.get_line("RRULE");
	if (piline == nullptr) {
		pdate->year = 0;
		pdate->month = itime.month;
		pdate->dayofweek = ical_get_dayofweek(
			itime.year, itime.month, itime.day);
		pdate->day = ical_get_monthweekorder(itime.day);
		return true;
	}
	pvalue = piline->get_first_subvalue_by_name("FREQ");
	if (pvalue == nullptr || strcasecmp(pvalue, "YEARLY") != 0)
		return false;
	pvalue = piline->get_first_subvalue_by_name("BYDAY");
	pvalue1 = piline->get_first_subvalue_by_name("BYMONTHDAY");
	if ((pvalue == nullptr && pvalue1 == nullptr) ||
	    (pvalue != nullptr && pvalue1 != nullptr))
		return false;
	pvalue2 = piline->get_first_subvalue_by_name("BYMONTH");
	if (pvalue2 == nullptr) {
		pdate->month = itime.month;
	} else {
		pdate->month = strtol(pvalue2, nullptr, 0);
		if (pdate->month < 1 || pdate->month > 12)
			return false;
	}
	if (pvalue != nullptr) {
		pdate->year = 0;
		if (!ical_parse_byday(pvalue, &dayofweek, &weekorder))
			return false;
		if (weekorder == -1)
			weekorder = 5;
		if (weekorder > 5 || weekorder < 1)
			return false;
		pdate->dayofweek = dayofweek;
		pdate->day = weekorder;
	} else {
		pdate->year = 1;
		pdate->dayofweek = 0;
		pdate->day = strtol(pvalue1, nullptr, 0);
		if (abs(pdate->day) < 1 || abs(pdate->day) > 31)
			return false;
	}
	return true;
}

static bool oxcical_parse_tzdefinition(const ical_component &vt,
	TIMEZONEDEFINITION *ptz_definition)
{
	int i;
	bool b_found;
	int16_t year;
	SYSTEMTIME date;
	bool b_daylight;
	TZRULE *pstandard_rule;
	TZRULE *pdaylight_rule;

	ptz_definition->major = 2;
	ptz_definition->minor = 1;
	ptz_definition->reserved = 0x0002;
	auto piline = vt.get_line("TZID");
	if (piline == nullptr)
		return false;
	ptz_definition->keyname = deconst(piline->get_first_subvalue());
	if (ptz_definition->keyname == nullptr)
		return false;
	ptz_definition->crules = 0;
	for (const auto &comp : vt.component_list) {
		auto pcomponent = &comp;
		if (strcasecmp(pcomponent->m_name.c_str(), "STANDARD") == 0)
			b_daylight = false;
		else if (strcasecmp(pcomponent->m_name.c_str(), "DAYLIGHT") == 0)
			b_daylight = true;
		else
			continue;
		int32_t bias = 0, dstbias = 0;
		if (!oxcical_parse_vtsubcomponent(*pcomponent, &bias, &dstbias, &year, &date))
			return false;
		b_found = false;
		for (i=0; i<ptz_definition->crules; i++) {
			if (year == ptz_definition->prules[i].year) {
				b_found = true;
				break;
			}
		}
		if (!b_found) {
			if (ptz_definition->crules >= MAX_TZRULE_NUMBER)
				return false;
			ptz_definition->crules ++;
			memset(ptz_definition->prules + i, 0, sizeof(TZRULE));
			ptz_definition->prules[i].major = 2;
			ptz_definition->prules[i].minor = 1;
			ptz_definition->prules[i].reserved = 0x003E;
			ptz_definition->prules[i].year = year;
		}
		if (b_daylight) {
			ptz_definition->prules[i].daylightbias = dstbias;
			ptz_definition->prules[i].daylightdate = date;
		} else {
			ptz_definition->prules[i].bias = bias;
			ptz_definition->prules[i].standarddate = date;
		}
	}
	if (ptz_definition->crules == 0)
		return false;
	std::sort(ptz_definition->prules, ptz_definition->prules + ptz_definition->crules);
	pstandard_rule = nullptr;
	pdaylight_rule = nullptr;
	for (i=0; i<ptz_definition->crules; i++) {
		if (0 != ptz_definition->prules[i].standarddate.month) {
			pstandard_rule = ptz_definition->prules + i;
		} else if (pstandard_rule != nullptr) {
			ptz_definition->prules[i].standarddate =
				pstandard_rule->standarddate;
			ptz_definition->prules[i].bias =
				pstandard_rule->bias;
		}
		if (0 != ptz_definition->prules[i].daylightdate.month) {
			pdaylight_rule = ptz_definition->prules + i;
		} else if (pdaylight_rule != nullptr) {
			ptz_definition->prules[i].daylightdate = pdaylight_rule->daylightdate;
			ptz_definition->prules[i].daylightbias = pdaylight_rule->daylightbias;
		}
		/* ignore the definition which has only STANDARD component
			or with the same STANDARD and DAYLIGHT component */
		if (ptz_definition->prules[i].daylightdate.month == 0 ||
		    memcmp(&ptz_definition->prules[i].standarddate,
		    &ptz_definition->prules[i].daylightdate, sizeof(SYSTEMTIME)) == 0)
			memset(&ptz_definition->prules[i].daylightdate,
				0, sizeof(SYSTEMTIME));
	}
	if (ptz_definition->crules > 1 &&
		(0 == ptz_definition->prules[0].standarddate.month ||
		0 == ptz_definition->prules[0].daylightdate.month) &&
		0 != ptz_definition->prules[1].standarddate.month &&
		0 != ptz_definition->prules[1].daylightdate.month) {
		ptz_definition->crules --;
		memmove(ptz_definition->prules, ptz_definition->prules + 1,
							sizeof(TZRULE)*ptz_definition->crules);
	}
	ptz_definition->prules[0].year = 1601;
	ptz_definition->prules[0].x[0] = 1;
	ptz_definition->prules[0].x[4] = 1;
	return true;
}

static void oxcical_convert_to_tzstruct(
	TIMEZONEDEFINITION *ptz_definition, TIMEZONESTRUCT *ptz_struct)
{
	memset(ptz_struct, 0, sizeof(TIMEZONESTRUCT));
	if (ptz_definition->crules == 0)
		return;
	int index;

	index = ptz_definition->crules - 1;
	ptz_struct->bias = ptz_definition->prules[index].bias;
	ptz_struct->daylightbias = ptz_definition->prules[index].daylightbias;
	ptz_struct->standarddate = ptz_definition->prules[index].standarddate;
	ptz_struct->daylightdate = ptz_definition->prules[index].daylightdate;
	ptz_struct->standardyear = ptz_struct->standarddate.year;
	ptz_struct->daylightyear = ptz_struct->daylightdate.year;
}

static bool oxcical_tzdefinition_to_binary(
	TIMEZONEDEFINITION *ptz_definition,
	uint16_t tzrule_flags, BINARY *pbin)
{
	EXT_PUSH ext_push;

	if (!ext_push.init(pbin->pb, MAX_TZDEFINITION_LENGTH, 0))
		return false;
	for (size_t i = 0; i < ptz_definition->crules; ++i)
		ptz_definition->prules[i].flags = tzrule_flags;
	if (ext_push.p_tzdef(*ptz_definition) != EXT_ERR_SUCCESS)
		return false;
	pbin->cb = ext_push.m_offset;
	return true;
}

static bool oxcical_timezonestruct_to_binary(
	TIMEZONESTRUCT *ptzstruct, BINARY *pbin)
{
	EXT_PUSH ext_push;

	if (!ext_push.init(pbin->pb, 256, 0) ||
	    ext_push.p_tzstruct(*ptzstruct) != EXT_ERR_SUCCESS)
		return false;
	pbin->cb = ext_push.m_offset;
	return true;
}

/* ptz_component can be NULL, represents UTC */
static bool oxcical_parse_rrule(const ical_component &tzcom,
    const ical_line &iline, uint16_t calendartype, time_t start_time,
    uint32_t duration_minutes, APPOINTMENT_RECUR_PAT *apr)
{
	time_t tmp_time;
	ical_time itime1;
	ical_rrule irrule;
	const char *pvalue;
	uint32_t patterntype = 0;
	const ical_time *pitime;

	auto piline = &iline;
	if (piline->get_subval_list("BYYEARDAY") != nullptr ||
	    piline->get_subval_list("BYWEEKNO") != nullptr)
		return false;
	auto psubval_list = piline->get_subval_list("BYMONTHDAY");
	if (psubval_list != nullptr && psubval_list->size() > 1)
		return false;
	psubval_list = piline->get_subval_list("BYSETPOS");
	if (psubval_list != nullptr && psubval_list->size() > 1)
		return false;
	psubval_list = piline->get_subval_list("BYSECOND");
	if (psubval_list != nullptr) {
		if (psubval_list->size() > 1)
			return false;
		pvalue = piline->get_first_subvalue_by_name("BYSECOND");
		if (pvalue != nullptr && strtol(pvalue, nullptr, 0) != start_time % 60)
			return false;
	}
	if (!ical_parse_rrule(&tzcom, start_time, &piline->value_list, &irrule))
		return false;
	auto b_exceptional = irrule.b_start_exceptional;
	if (b_exceptional && !irrule.iterate())
		return false;
	ical_time itime_base = irrule.base_itime, itime_first = irrule.instance_itime;
	apr->readerversion2 = 0x3006;
	apr->writerversion2 = 0x3009;
	apr->recur_pat.readerversion = 0x3004;
	apr->recur_pat.writerversion = 0x3004;
	apr->recur_pat.slidingflag = 0;
	apr->recur_pat.firstdow = irrule.weekstart;
	auto itime = irrule.instance_itime;
	apr->starttimeoffset = 60 * itime.hour + itime.minute;
	apr->endtimeoffset = apr->starttimeoffset + duration_minutes;
	itime.hour = 0;
	itime.minute = 0;
	itime.second = 0;
	ical_itime_to_utc(nullptr, itime, &tmp_time);
	apr->recur_pat.startdate = rop_util_unix_to_rtime(tmp_time);
	if (irrule.endless()) {
 SET_INFINITE:
		apr->recur_pat.endtype = IDC_RCEV_PAT_ERB_NOEND;
		apr->recur_pat.occurrencecount = 10;
		apr->recur_pat.enddate = ENDDATE_MISSING;
	} else {
		itime = irrule.instance_itime;
		while (irrule.iterate()) {
			itime1 = irrule.instance_itime;
			if (itime1.year > 4500)
				goto SET_INFINITE;
			/* instances can not be in same day */
			if (itime1.year == itime.year &&
				itime1.month == itime.month &&
			    itime1.day == itime.day)
				return false;
			itime = itime1;
		}
		if (irrule.total_count != 0) {
			apr->recur_pat.endtype = IDC_RCEV_PAT_ERB_AFTERNOCCUR;
			apr->recur_pat.occurrencecount = irrule.total_count;
		} else {
			apr->recur_pat.endtype = IDC_RCEV_PAT_ERB_END;
			apr->recur_pat.occurrencecount = irrule.sequence();
		}
		if (b_exceptional)
			--apr->recur_pat.occurrencecount;
		pitime = irrule.get_until_itime();
		itime = pitime != nullptr ? *pitime : irrule.instance_itime;
		itime.hour = 0;
		itime.minute = 0;
		itime.second = 0;
		ical_itime_to_utc(nullptr, itime, &tmp_time);
		apr->recur_pat.enddate = rop_util_unix_to_rtime(tmp_time);
	}
	switch (irrule.frequency) {
	case ical_frequency::second:
	case ical_frequency::minute:
	case ical_frequency::hour:
		return false;
	case ical_frequency::day:
		if (piline->get_subval_list("BYDAY") != nullptr ||
		    piline->get_subval_list("BYMONTH") != nullptr ||
		    piline->get_subval_list("BYSETPOS") != nullptr)
			return false;
		apr->recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_DAILY;
		if (irrule.interval > 999)
			return false;
		apr->recur_pat.period = irrule.interval * 1440;
		apr->recur_pat.firstdatetime = apr->recur_pat.startdate % apr->recur_pat.period;
		patterntype = rptMinute;
		break;
	case ical_frequency::week:
		if (piline->get_subval_list("BYMONTH") != nullptr ||
		    piline->get_subval_list("BYSETPOS") != nullptr)
			return false;
		apr->recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_WEEKLY;
		if (irrule.interval > 99)
			return false;
		apr->recur_pat.period = irrule.interval;
		itime = itime_base;
		itime.hour = 0;
		itime.minute = 0;
		itime.second = 0;
		itime.leap_second = 0;
		ical_itime_to_utc(nullptr, itime, &tmp_time);
		apr->recur_pat.firstdatetime = rop_util_unix_to_rtime(tmp_time) %
			(10080 * irrule.interval);
		patterntype = rptWeek;
		if (irrule.test_bymask(rrule_by::day)) {
			psubval_list = piline->get_subval_list("BYDAY");
			apr->recur_pat.pts.weekrecur = 0;
			for (const auto &pnv2 : *psubval_list) {
				auto wd = weekday_to_int(pnv2.c_str());
				if (wd < 0)
					continue;
				apr->recur_pat.pts.weekrecur |= 1 << wd;
			}
		} else {
			ical_utc_to_datetime(&tzcom, start_time, &itime);
			apr->recur_pat.pts.weekrecur = 1U << ical_get_dayofweek(itime.year, itime.month, itime.day);
		}
		break;
	case ical_frequency::month:
		if (piline->get_subval_list("BYMONTH") != nullptr)
			return false;
		apr->recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_MONTHLY;
		if (irrule.interval > 99)
			return false;
		apr->recur_pat.period = irrule.interval;
		itime = {};
		itime.year = 1601;
		itime.month = ((itime_base.year - 1601) * 12 + itime_base.month - 1) %
		              irrule.interval + 1;
		itime.year += itime.month/12;
		itime.month = (itime.month - 1) % 12 + 1;
		itime.day = 1;
		itime1 = {};
		itime1.year = 1601;
		itime1.month = 1;
		itime1.day = 1;
		apr->recur_pat.firstdatetime = itime.delta_day(itime1) * 1440;
		if (irrule.test_bymask(rrule_by::day) &&
		    irrule.test_bymask(rrule_by::setpos)) {
			patterntype = rptMonthNth;
			psubval_list = piline->get_subval_list("BYDAY");
			apr->recur_pat.pts.monthnth.weekrecur = 0;
			for (const auto &pnv2 : *psubval_list) {
				auto wd = weekday_to_int(pnv2.c_str());
				if (wd < 0)
					continue;
				apr->recur_pat.pts.monthnth.weekrecur |= 1 << wd;
			}
			pvalue = piline->get_first_subvalue_by_name("BYSETPOS");
			int tmp_int = strtol(pvalue, nullptr, 0);
			if (tmp_int > 4 || tmp_int < -1)
				return false;
			else if (tmp_int == -1)
				tmp_int = 5;
			apr->recur_pat.pts.monthnth.recurnum = tmp_int;
		} else {
			/* Cf. RFC 5545 pg. 43, "rule: BY_SETPOS" */
			if (irrule.test_bymask(rrule_by::day) &&
			    !irrule.test_bymask(rrule_by::setpos))
				return false;
			int tmp_int;
			patterntype = rptMonth;
			pvalue = piline->get_first_subvalue_by_name("BYMONTHDAY");
			if (pvalue == nullptr) {
				ical_utc_to_datetime(&tzcom, start_time, &itime);
				tmp_int = itime.day;
			} else {
				tmp_int = strtol(pvalue, nullptr, 0);
				if (tmp_int < -1)
					return false;
				else if (tmp_int == -1)
					tmp_int = 31;
			}
			apr->recur_pat.pts.dayofmonth = tmp_int;
		}
		break;
	case ical_frequency::year:
		apr->recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_YEARLY;
		if (irrule.interval > 8)
			return false;
		apr->recur_pat.period = 12 * irrule.interval;
		itime = {};
		itime.year = 1601;
		itime.month = (itime_first.month - 1) % (12 * irrule.interval);
		itime.year += itime.month/12;
		itime.month = itime.month % 12 + 1;
		itime.day = 1;
		itime1 = {};
		itime1.year = 1601;
		itime1.month = 1;
		itime1.day = 1;
		apr->recur_pat.firstdatetime = itime.delta_day(itime1) * 1440;
		if (irrule.test_bymask(rrule_by::day) &&
		    irrule.test_bymask(rrule_by::setpos) &&
		    irrule.test_bymask(rrule_by::month)) {
			if (irrule.test_bymask(rrule_by::monthday))
				return false;
			patterntype = rptMonthNth;
			psubval_list = piline->get_subval_list("BYDAY");
			apr->recur_pat.pts.monthnth.weekrecur = 0;
			for (const auto &pnv2 : *psubval_list) {
				auto wd = weekday_to_int(pnv2.c_str());
				if (wd < 0)
					continue;
				apr->recur_pat.pts.monthnth.weekrecur |= 1 << wd;
			}
			pvalue = piline->get_first_subvalue_by_name("BYSETPOS");
			int tmp_int = strtol(pvalue, nullptr, 0);
			if (tmp_int > 4 || tmp_int < -1)
				return false;
			else if (tmp_int == -1)
				tmp_int = 5;
			apr->recur_pat.pts.monthnth.recurnum = tmp_int;
		} else {
			if (irrule.test_bymask(rrule_by::day) ||
			    irrule.test_bymask(rrule_by::setpos))
				return false;
			int tmp_int;
			patterntype = rptMonth;
			pvalue = piline->get_first_subvalue_by_name("BYMONTHDAY");
			if (pvalue == nullptr) {
				ical_utc_to_datetime(&tzcom, start_time, &itime);
				tmp_int = itime.day;
			} else {
				tmp_int = strtol(pvalue, nullptr, 0);
				if (tmp_int < -1)
					return false;
				else if (tmp_int == -1)
					tmp_int = 31;
			}
			apr->recur_pat.pts.dayofmonth = tmp_int;
		}
		break;
	}
	if (calendartype == CAL_HIJRI) {
		if (patterntype == rptMonth) {
			patterntype  = rptHjMonth;
			calendartype = CAL_DEFAULT;
		} else if (patterntype == rptMonthNth) {
			patterntype  = rptHjMonthNth;
			calendartype = CAL_DEFAULT;
		}
	}
	apr->recur_pat.patterntype = patterntype;
	apr->recur_pat.calendartype = calendartype;
	return true;
}

static const ical_component *oxcical_find_vtimezone(const ical &pical, const char *tzid)
{
	const char *pvalue;

	for (const auto &comp : pical.component_list) {
		auto pcomponent = &comp;
		if (strcasecmp(pcomponent->m_name.c_str(), "VTIMEZONE") != 0)
			continue;
		auto piline = pcomponent->get_line("TZID");
		if (piline == nullptr)
			continue;
		pvalue = piline->get_first_subvalue();
		if (pvalue == nullptr)
			continue;
		if (strcasecmp(pvalue, tzid) == 0)
			return pcomponent;
	}
	return nullptr;
}

static bool oxcical_parse_tzdisplay(bool b_dtstart, const ical_component &tzcom,
    namemap &phash, uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	TIMEZONEDEFINITION tz_definition;
	TZRULE rules_buff[MAX_TZRULE_NUMBER];
	uint8_t bin_buff[MAX_TZDEFINITION_LENGTH];

	tz_definition.prules = rules_buff;
	if (!oxcical_parse_tzdefinition(tzcom, &tz_definition))
		return false;
	if (tz_definition.crules == 0) {
		mlog(LV_DEBUG, "Rejecting conversion of iCal to MAPI object: no sensible TZ rules found (e.g. RFC 5545 §3.6.5 VTIMEZONE without STANDARD/DAYLIGHT not permitted)");
		return false;
	}
	tmp_bin.pb = bin_buff;
	tmp_bin.cb = 0;
	if (!oxcical_tzdefinition_to_binary(&tz_definition,
	    TZRULE_FLAG_EFFECTIVE_TZREG, &tmp_bin))
		return false;
	PROPERTY_NAME propname = {MNID_ID, PSETID_Appointment, b_dtstart ?
		PidLidAppointmentTimeZoneDefinitionStartDisplay :
		PidLidAppointmentTimeZoneDefinitionEndDisplay};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return false;
	if (pmsg->proplist.set(PROP_TAG(PT_BINARY, *plast_propid), &tmp_bin) != 0)
		return false;
	(*plast_propid) ++;
	return true;
}

static bool oxcical_parse_recurring_timezone(const ical_component &tzcom,
    namemap &phash, uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	const char *ptzid;
	TIMEZONESTRUCT tz_struct;
	TIMEZONEDEFINITION tz_definition;
	TZRULE rules_buff[MAX_TZRULE_NUMBER];
	uint8_t bin_buff[MAX_TZDEFINITION_LENGTH];

	tz_definition.prules = rules_buff;
	if (!oxcical_parse_tzdefinition(tzcom, &tz_definition))
		return false;
	auto piline = tzcom.get_line("TZID");
	if (piline == nullptr)
		return false;
	ptzid = piline->get_first_subvalue();
	if (ptzid == nullptr)
		return false;
	PROPERTY_NAME propname = {MNID_ID, PSETID_Appointment, PidLidTimeZoneDescription};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return false;
	if (pmsg->proplist.set(PROP_TAG(PT_UNICODE, *plast_propid), ptzid) != 0)
		return false;
	(*plast_propid) ++;
	oxcical_convert_to_tzstruct(&tz_definition, &tz_struct);
	tmp_bin.pb = bin_buff;
	tmp_bin.cb = 0;
	if (!oxcical_timezonestruct_to_binary(&tz_struct, &tmp_bin))
		return false;
	propname = {MNID_ID, PSETID_Appointment, PidLidTimeZoneStruct};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return false;
	if (pmsg->proplist.set(PROP_TAG(PT_BINARY, *plast_propid), &tmp_bin) != 0)
		return false;
	(*plast_propid) ++;
	tmp_bin.pb = bin_buff;
	tmp_bin.cb = 0;
	if (!oxcical_tzdefinition_to_binary(&tz_definition,
	    TZRULE_FLAG_EFFECTIVE_TZREG | TZRULE_FLAG_RECUR_CURRENT_TZREG, &tmp_bin))
		return false;
	propname = {MNID_ID, PSETID_Appointment, PidLidAppointmentTimeZoneDefinitionRecur};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return false;
	if (pmsg->proplist.set(PROP_TAG(PT_BINARY, *plast_propid), &tmp_bin) != 0)
		return false;
	(*plast_propid) ++;
	return true;
}

static bool oxcical_parse_proposal(namemap &phash,
	uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	uint8_t tmp_byte;
	PROPERTY_NAME pn = {MNID_ID, PSETID_Appointment, PidLidAppointmentCounterProposal};
	if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
		return false;
	tmp_byte = 1;
	if (pmsg->proplist.set(PROP_TAG(PT_BOOLEAN, *plast_propid), &tmp_byte) != 0)
		return false;
	(*plast_propid) ++;
	return true;
}

static unsigned int role_to_rcpttype(const char *r, const char *cu)
{
	/* Cf. OXCICAL v13 §2.1.3.1.1.20.2 */
	if (r == nullptr || strcasecmp(r, "chair") == 0 ||
	    strcasecmp(r, "req-participant") == 0)
		return MAPI_TO;
	if (strcasecmp(r, "opt-participant") == 0)
		return MAPI_CC;
	if (cu != nullptr && (strcasecmp(cu, "resource") == 0 ||
	    strcasecmp(cu, "room") == 0))
		return MAPI_BCC;
	if (strcasecmp(r, "non-participant") == 0)
		return MAPI_CC; /* OL2007 behavior */
	return MAPI_TO;
}

static bool oxcical_parse_recipients(const ical_component &main_ev,
	USERNAME_TO_ENTRYID username_to_entryid, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	uint8_t tmp_byte;
	const char *prole;
	const char *prsvp;
	uint32_t tmp_int32;
	TARRAY_SET *prcpts;
	uint8_t tmp_buff[1024];
	const char *paddress;
	TPROPVAL_ARRAY *pproplist;
	const char *pdisplay_name;

	auto pmessage_class = pmsg->proplist.get<const char>(PR_MESSAGE_CLASS);
	if (pmessage_class == nullptr)
		pmessage_class = pmsg->proplist.get<char>(PR_MESSAGE_CLASS_A);
	if (pmessage_class == nullptr)
		pmessage_class = "IPM.Note";
	/* ignore ATTENDEE when METHOD is "PUBLIC" */
	if (class_match_prefix(pmessage_class, "IPM.Appointment") == 0)
		return true;
	prcpts = tarray_set_init();
	if (prcpts == nullptr)
		return false;
	tmp_byte = 0;
	pmsg->set_rcpts_internal(prcpts);
	for (const auto &line : main_ev.line_list) {
		auto piline = &line;
		/* Cf. [MS-OXCICAL] v20240416 §2.1.3.1.1.20.16 "property: ORGANIZER". */
		auto is_attendee  = strcasecmp(piline->m_name.c_str(), "ATTENDEE") == 0;
		auto is_organizer = strcasecmp(piline->m_name.c_str(), "ORGANIZER") == 0;
		if (!is_attendee && !is_organizer)
			continue;
		paddress = piline->get_first_subvalue();
		if (paddress == nullptr || strncasecmp(paddress, "MAILTO:", 7) != 0)
			continue;
		paddress += 7;
		pdisplay_name = piline->get_first_paramval("CN");
		auto cutype = piline->get_first_paramval("CUTYPE");
		prole = piline->get_first_paramval("ROLE");
		prsvp = piline->get_first_paramval("RSVP");
		if (prsvp != nullptr && strcasecmp(prsvp, "TRUE") == 0)
			tmp_byte = 1;
		pproplist = prcpts->emplace();
		if (pproplist == nullptr)
			return false;
		if (pproplist->set(PR_ADDRTYPE, "SMTP") != 0 ||
		    pproplist->set(PR_EMAIL_ADDRESS, paddress) != 0 ||
		    pproplist->set(PR_SMTP_ADDRESS, paddress) != 0)
			return false;
		if (pdisplay_name == nullptr)
			pdisplay_name = paddress;
		if (pproplist->set(PR_DISPLAY_NAME, pdisplay_name) != 0 ||
		    pproplist->set(PR_TRANSMITABLE_DISPLAY_NAME, pdisplay_name) != 0)
			return false;
		tmp_bin.pb = tmp_buff;
		tmp_bin.cb = 0;
		auto dtypx = DT_MAILUSER;
		if (!username_to_entryid(paddress, pdisplay_name, &tmp_bin, &dtypx) ||
		    pproplist->set(PR_ENTRYID, &tmp_bin) != 0 ||
		    pproplist->set(PR_RECIPIENT_ENTRYID, &tmp_bin) != 0 ||
		    pproplist->set(PR_RECORD_KEY, &tmp_bin) != 0)
			return false;
		tmp_int32 = role_to_rcpttype(prole, cutype);
		if (pproplist->set(PR_RECIPIENT_TYPE, &tmp_int32) != 0)
			return false;
		tmp_int32 = static_cast<uint32_t>(dtypx == DT_DISTLIST ? MAPI_DISTLIST : MAPI_MAILUSER);
		if (pproplist->set(PR_OBJECT_TYPE, &tmp_int32) != 0)
			return false;
		tmp_int32 = static_cast<uint32_t>(dtypx);
		if (pproplist->set(PR_DISPLAY_TYPE, &tmp_int32) != 0)
			return false;
		tmp_byte = 1;
		if (pproplist->set(PR_RESPONSIBILITY, &tmp_byte) != 0)
			return false;
		tmp_int32 = recipSendable;
		if (is_organizer)
			tmp_int32 |= recipOrganizer;
		if (pproplist->set(PR_RECIPIENT_FLAGS, &tmp_int32) != 0)
			return false;
	}
	/*
	 * XXX: Value of tmp_byte is unclear, but it appears it coincides with
	 * the presence of any recipients.
	 */
	if (pmsg->proplist.set(PR_RESPONSE_REQUESTED, &tmp_byte) != 0 ||
	    pmsg->proplist.set(PR_REPLY_REQUESTED, &tmp_byte) != 0)
		return false;
	return true;
}

static bool oxcical_parse_categories(const ical_component &main_event,
   namemap &phash, uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	auto piline = main_event.get_line("CATEGORIES");
	if (piline == nullptr)
		return true;

	char *tmp_buff[128];
	STRING_ARRAY strings_array;

	if (piline->value_list.size() == 0)
		return true;
	auto &pivalue = piline->value_list.front();
	strings_array.count = 0;
	strings_array.ppstr = tmp_buff;
	for (const auto &pnv2 : pivalue.subval_list) {
		if (pnv2.empty())
			continue;
		strings_array.ppstr[strings_array.count++] = deconst(pnv2.c_str());
		if (strings_array.count >= 128)
			break;
	}
	if (0 != strings_array.count && strings_array.count < 128) {
		PROPERTY_NAME pn = {MNID_STRING, PS_PUBLIC_STRINGS, 0, deconst(PidNameKeywords)};
		if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
			return false;
		if (pmsg->proplist.set(PROP_TAG(PT_MV_UNICODE, *plast_propid), &strings_array) != 0)
			return false;
		(*plast_propid) ++;
	}
	return true;
}

static bool oxcical_parse_class(const ical_component &main_event,
    MESSAGE_CONTENT *pmsg)
{
	auto piline = main_event.get_line("CLASS");
	if (piline == nullptr) {
		uint32_t v = SENSITIVITY_NONE;
		if (pmsg->proplist.set(PR_SENSITIVITY, &v) != 0)
			return false;
		return true;
	}

	uint32_t tmp_int32;
	const char *pvalue;

	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return true;
	if (strcasecmp(pvalue, "PERSONAL") == 0 ||
	    strcasecmp(pvalue, "X-PERSONAL") == 0)
		tmp_int32 = SENSITIVITY_PERSONAL;
	else if (strcasecmp(pvalue, "PRIVATE") == 0)
		tmp_int32 = SENSITIVITY_PRIVATE;
	else if (strcasecmp(pvalue, "CONFIDENTIAL") == 0)
		tmp_int32 = SENSITIVITY_COMPANY_CONFIDENTIAL;
	else if (strcasecmp(pvalue, "PUBLIC"))
		tmp_int32 = SENSITIVITY_NONE;
	else
		return true;
	if (pmsg->proplist.set(PR_SENSITIVITY, &tmp_int32) != 0)
		return false;
	return true;
}

static bool oxcical_parse_body(const ical_component &main_event,
    const char *method, MESSAGE_CONTENT *pmsg)
{
	const char *linetype = "DESCRIPTION";
	if (method != nullptr && (strcasecmp(method, "reply") == 0 ||
	    strcasecmp(method, "counter") == 0))
		linetype = "COMMENT";
	auto piline = main_event.get_line(linetype);
	if (piline == nullptr)
		return true;

	const char *pvalue;

	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return true;
	if (pmsg->proplist.set(PR_BODY, pvalue) != 0)
		return false;
	return true;
}

static bool oxcical_parse_html(const ical_component &main_event,
    MESSAGE_CONTENT *pmsg)
{
	auto piline = main_event.get_line("X-ALT-DESC");
	if (piline == nullptr)
		return true;
	auto pvalue = piline->get_first_paramval("FMTTYPE");
	if (pvalue == nullptr || strcasecmp(pvalue, "text/html") != 0)
		return true;

	BINARY tmp_bin;
	uint32_t tmp_int32;

	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return true;
	tmp_bin.cb = strlen(pvalue);
	tmp_bin.pc = deconst(pvalue);
	if (pmsg->proplist.set(PR_HTML, &tmp_bin) != 0)
		return false;
	tmp_int32 = CP_UTF8;
	if (pmsg->proplist.set(PR_INTERNET_CPID, &tmp_int32) != 0)
		return false;
	return true;
}

static bool oxcical_parse_dtstamp(const ical_component &main_event,
    const char *method, namemap &phash,
	uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	auto piline = main_event.get_line("DTSTAMP");
	if (piline == nullptr)
		return true;

	time_t tmp_time;
	uint64_t tmp_int64;
	const char *pvalue;

	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return true;
	if (!ical_datetime_to_utc(nullptr, pvalue, &tmp_time))
		return true;
	PROPERTY_NAME propname = {MNID_ID, PSETID_Meeting};
	propname.lid = (method != nullptr && (strcasecmp(method, "REPLY") == 0 ||
	                strcasecmp(method, "COUNTER") == 0)) ?
	               PidLidAttendeeCriticalChange : PidLidOwnerCriticalChange;
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return false;
	tmp_int64 = rop_util_unix_to_nttime(tmp_time);
	if (pmsg->proplist.set(PROP_TAG(PT_SYSTIME, *plast_propid), &tmp_int64) != 0)
		return false;
	(*plast_propid) ++;
	return true;
}

static bool oxcical_parse_start_end(bool b_start, bool b_proposal,
    const ical_component &pmain_event, time_t unix_time,
    namemap &phash, uint16_t *plast_propid,  MESSAGE_CONTENT *pmsg)
{
	uint16_t comid = b_start ? PidLidCommonStart : PidLidCommonEnd;
	uint32_t sdtag = b_start ? PR_START_DATE : PR_END_DATE;
	uint64_t tmp_int64;

	tmp_int64 = rop_util_unix_to_nttime(unix_time);
	if (b_proposal) {
		PROPERTY_NAME pn = {MNID_ID, PSETID_Appointment, b_start ?
			PidLidAppointmentProposedStartWhole :
			PidLidAppointmentProposedEndWhole};
		if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
			return false;
		if (pmsg->proplist.set(PROP_TAG(PT_SYSTIME, *plast_propid), &tmp_int64) != 0)
			return false;
		(*plast_propid) ++;
		pn = {MNID_ID, PSETID_Common, comid};
		if (namemap_add(phash, *plast_propid, std::move(pn)) != 0 ||
		    pmsg->proplist.set(PROP_TAG(PT_SYSTIME, *plast_propid), &tmp_int64) != 0 ||
		    pmsg->proplist.set(sdtag, &tmp_int64) != 0)
			return false;
		++*plast_propid;
	}
	if (!b_proposal ||
	    (pmain_event.get_line("X-MS-OLK-ORIGINALEND") == nullptr &&
	    pmain_event.get_line("X-MS-OLK-ORIGINALSTART") == nullptr)) {
		PROPERTY_NAME pn = {MNID_ID, PSETID_Appointment, b_start ?
			PidLidAppointmentStartWhole : PidLidAppointmentEndWhole};
		if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
			return false;
		if (pmsg->proplist.set(PROP_TAG(PT_SYSTIME, *plast_propid), &tmp_int64) != 0)
			return false;
		(*plast_propid) ++;
		pn = {MNID_ID, PSETID_Common, comid};
		if (namemap_add(phash, *plast_propid, std::move(pn)) != 0 ||
		    pmsg->proplist.set(PROP_TAG(PT_SYSTIME, *plast_propid), &tmp_int64) != 0 ||
		    pmsg->proplist.set(sdtag, &tmp_int64) != 0)
			return false;
		++*plast_propid;
	}
	return true;
}

static bool oxcical_parse_subtype(namemap &phash, uint16_t *plast_propid,
    MESSAGE_CONTENT *pmsg, EXCEPTIONINFO *pexception)
{
	uint8_t tmp_byte;
	PROPERTY_NAME pn = {MNID_ID, PSETID_Appointment, PidLidAppointmentSubType};
	if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
		return false;
	tmp_byte = 1;
	if (pmsg->proplist.set(PROP_TAG(PT_BOOLEAN, *plast_propid), &tmp_byte) != 0)
		return false;
	(*plast_propid) ++;
	if (pexception != nullptr) {
		pexception->overrideflags |= ARO_SUBTYPE;
		pexception->subtype = 1;
	}
	return true;
}

static bool oxcical_parse_dates(const ical_component *ptz_component,
    const ical_line &iline, uint32_t *pcount, uint32_t *pdates)
{
	time_t tmp_time;
	uint32_t tmp_date;
	const char *pvalue;

	auto piline = &iline;
	if (piline->value_list.size() == 0)
		return true;
	*pcount = 0;
	auto &pivalue = piline->value_list.front();
	pvalue = piline->get_first_paramval("VALUE");
	if (pvalue == nullptr || strcasecmp(pvalue, "DATE-TIME") == 0) {
		for (const auto &pnv2 : pivalue.subval_list) {
			if (pnv2.empty())
				continue;
			ical_time itime{};
			if (!ical_parse_datetime(pnv2.c_str(), &itime))
				continue;
			if (itime.type == ICT_UTC && ptz_component != nullptr) {
				/* Adjust itime to be in local time */
				ical_itime_to_utc(nullptr, itime, &tmp_time);
				ical_utc_to_datetime(ptz_component, tmp_time, &itime);
				/* return value not checked -- could oddly be an ICT_FLOAT now */
			}
			itime.hour = 0;
			itime.minute = 0;
			itime.second = 0;
			ical_itime_to_utc(nullptr, itime, &tmp_time);
			tmp_date = rop_util_unix_to_rtime(tmp_time);
			for (size_t i = 0; i < *pcount; ++i)
				if (tmp_date == pdates[i])
					return true;
			pdates[*pcount] = tmp_date;
			(*pcount) ++;
			if (*pcount >= 1024)
				return true;
		}
	} else if (0 == strcasecmp(pvalue, "DATE")) {
		for (const auto &pnv2 : pivalue.subval_list) {
			if (pnv2.empty())
				continue;
			ical_time itime{};
			if (!ical_parse_date(pnv2.c_str(), &itime))
				continue;
			ical_itime_to_utc(nullptr, itime, &tmp_time);
			pdates[*pcount] = rop_util_unix_to_rtime(tmp_time);
			(*pcount) ++;
			if (*pcount >= 1024)
				return true;
		}
	} else {
		return false;
	}
	return true;
}

static bool oxcical_parse_duration(uint32_t minutes, namemap &phash,
    uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	PROPERTY_NAME pn = {MNID_ID, PSETID_Appointment, PidLidAppointmentDuration};
	if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
		return false;
	if (pmsg->proplist.set(PROP_TAG(PT_LONG, *plast_propid), &minutes) != 0)
		return false;
	(*plast_propid) ++;
	return true;
}

static bool oxcical_parse_dtvalue(const ical_component *ptz_component,
    const ical_line &piline, ical_time *pitime, time_t *putc_time)
{
	auto pvalue = piline.get_first_subvalue();
	if (pvalue == nullptr)
		return false;
	time_t dummy_time;
	if (putc_time == nullptr)
		/* Caller does not care about result */
		putc_time = &dummy_time;
	auto pvalue1 = piline.get_first_paramval("VALUE");
	if (pvalue1 == nullptr || strcasecmp(pvalue1, "DATE-TIME") == 0) {
		if (!ical_parse_datetime(pvalue, pitime)) {
			if (pvalue1 == nullptr)
				goto PARSE_DATE_VALUE;
			return false;
		}
		if (pitime->type == ICT_UTC) {
			if (!ical_itime_to_utc(nullptr, *pitime, putc_time))
				return false;
		} else {
			if (pitime->type == ICT_FLOAT && ptz_component != nullptr)
				pitime->type = ICT_LOCAL;
			if (!ical_itime_to_utc(ptz_component,
			    *pitime, putc_time))
				return false;
		}
	} else if (0 == strcasecmp(pvalue1, "DATE")) {
 PARSE_DATE_VALUE:
		*pitime = {};
		if (!ical_parse_date(pvalue, pitime))
			return false;
		if (pitime->type == ICT_FLOAT && ptz_component != nullptr)
			pitime->type = ICT_LOCAL;
		if (!ical_itime_to_utc(ptz_component, *pitime, putc_time))
			return false;
	} else {
		return false;
	}
	return true;
}

static bool oxcical_parse_uid(const ical_component &main_event,
    ical_time effective_itime, EXT_BUFFER_ALLOC alloc, namemap &phash,
    uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	auto piline = main_event.get_line("UID");
	if (piline == nullptr)
		return true;

	BINARY tmp_bin;
	EXT_PULL ext_pull;
	EXT_PUSH ext_push;
	const char *pvalue;
	char tmp_buff[1024];
	GLOBALOBJECTID globalobjectid;

	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return true;
	auto tmp_len = strlen(pvalue);
	if (strncasecmp(pvalue, EncodedGlobalId_hex, 32) == 0 &&
	    decode_hex_binary(pvalue, tmp_buff, std::size(tmp_buff))) {
		ext_pull.init(tmp_buff, tmp_len / 2, alloc, 0);
		if (ext_pull.g_goid(&globalobjectid) == EXT_ERR_SUCCESS &&
		    ext_pull.m_offset == tmp_len / 2) {
			if (globalobjectid.year < 1601 || globalobjectid.year > 4500 ||
				globalobjectid.month > 12 || 0 == globalobjectid.month ||
				globalobjectid.day > ical_get_monthdays(
				globalobjectid.year, globalobjectid.month)) {
				globalobjectid.year = effective_itime.year;
				globalobjectid.month = effective_itime.month;
				globalobjectid.day = effective_itime.day;
			}
			goto MAKE_GLOBALOBJID;
		}
	}
	memset(&globalobjectid, 0, sizeof(GLOBALOBJECTID));
	globalobjectid.arrayid = EncodedGlobalId;
	globalobjectid.year = effective_itime.year;
	globalobjectid.month = effective_itime.month;
	globalobjectid.day = effective_itime.day;
	globalobjectid.creationtime = 0;
	globalobjectid.data.cb = 12 + tmp_len;
	globalobjectid.data.pv = alloc(globalobjectid.data.cb);
	if (globalobjectid.data.pv == nullptr)
		return false;
	static_assert(sizeof(ThirdPartyGlobalId) == 12);
	memcpy(globalobjectid.data.pb, ThirdPartyGlobalId, 12);
	memcpy(globalobjectid.data.pb + 12, pvalue, tmp_len);
 MAKE_GLOBALOBJID:
	if (!ext_push.init(tmp_buff, 1024, 0) ||
	    ext_push.p_goid(globalobjectid) != EXT_ERR_SUCCESS)
		return false;
	tmp_bin.cb = ext_push.m_offset;
	tmp_bin.pc = tmp_buff;
	PROPERTY_NAME propname = {MNID_ID, PSETID_Meeting, PidLidGlobalObjectId};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return false;
	if (pmsg->proplist.set(PROP_TAG(PT_BINARY, *plast_propid), &tmp_bin) != 0)
		return false;
	(*plast_propid) ++;
	globalobjectid.year = 0;
	globalobjectid.month = 0;
	globalobjectid.day = 0;
	if (!ext_push.init(tmp_buff, 1024, 0) ||
	    ext_push.p_goid(globalobjectid) != EXT_ERR_SUCCESS)
		return false;
	tmp_bin.cb = ext_push.m_offset;
	tmp_bin.pc = tmp_buff;
	propname = {MNID_ID, PSETID_Meeting, PidLidCleanGlobalObjectId};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return false;
	if (pmsg->proplist.set(PROP_TAG(PT_BINARY, *plast_propid), &tmp_bin) != 0)
		return false;
	(*plast_propid) ++;
	return true;
}

static bool oxcical_parse_location(const ical_component &main_event,
    namemap &phash, uint16_t *plast_propid, EXT_BUFFER_ALLOC alloc,
	MESSAGE_CONTENT *pmsg, EXCEPTIONINFO *pexception,
	EXTENDEDEXCEPTION *pext_exception)
{
	auto piline = main_event.get_line("LOCATION");
	if (piline == nullptr)
		return true;

	int i;
	int tmp_len;
	const char *pvalue;
	char tmp_buff[1024];

	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return true;
	tmp_len = strlen(pvalue);
	if (tmp_len >= 1024)
		return true;
	memcpy(tmp_buff, pvalue, tmp_len + 1);
	if (!utf8_truncate(tmp_buff, 255))
		return true;
	tmp_len = strlen(tmp_buff);
	for (i=0; i<tmp_len; i++) {
		if ('\r' == tmp_buff[i] || '\n' == tmp_buff[i]) {
			memmove(tmp_buff + i, tmp_buff + i + 1, tmp_len - i);
			tmp_len --;
		}
	}
	PROPERTY_NAME propname = {MNID_ID, PSETID_Appointment, PidLidLocation};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return false;
	if (pmsg->proplist.set(PROP_TAG(PT_UNICODE, *plast_propid), tmp_buff) != 0)
		return false;
	(*plast_propid) ++;
	pvalue = piline->get_first_paramval("ALTREP");
	if (pvalue == nullptr)
		return true;
	propname = {MNID_STRING, PS_PUBLIC_STRINGS, 0, deconst(PidNameLocationUrl)};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return false;
	if (pmsg->proplist.set(PROP_TAG(PT_UNICODE, *plast_propid), pvalue) != 0)
		return false;
	(*plast_propid) ++;
	if (pexception != nullptr && pext_exception != nullptr) {
		pexception->overrideflags |= ARO_LOCATION;
		pexception->location = static_cast<char *>(alloc(tmp_len + 1));
		if (pexception->location == nullptr)
			return false;
		strcpy(pexception->location, tmp_buff);
		pext_exception->location = static_cast<char *>(alloc(tmp_len + 1));
		if (pext_exception->location == nullptr)
			return false;
		strcpy(pext_exception->location, tmp_buff);
	}
	return true;
}

static bool oxcical_parse_organizer(const ical_component &main_event,
	USERNAME_TO_ENTRYID username_to_entryid, MESSAGE_CONTENT *pmsg)
{
	auto piline = main_event.get_line("ORGANIZER");
	if (piline == nullptr)
		return true;
	BINARY tmp_bin;
	uint8_t tmp_buff[1024];
	const char *paddress;
	const char *pdisplay_name;

	auto pvalue = pmsg->proplist.get<const char>(PR_MESSAGE_CLASS);
	if (pvalue == nullptr)
		pvalue = pmsg->proplist.get<char>(PR_MESSAGE_CLASS_A);
	if (pvalue == nullptr)
		pvalue = "IPM.Note";
	/* ignore ORGANIZER when METHOD is "REPLY" OR "COUNTER" */
	if (class_match_prefix(pvalue, "IPM.Schedule.Meeting.Resp") == 0)
		return true;
	paddress = piline->get_first_subvalue();
	if (paddress != nullptr) {
		if (strncasecmp(paddress, "MAILTO:", 7) == 0)
			paddress += 7;
		else
			paddress = nullptr;
	}
	pdisplay_name = piline->get_first_paramval("CN");
	if (pdisplay_name != nullptr) {
		if (pmsg->proplist.set(PR_SENT_REPRESENTING_NAME, pdisplay_name) != 0)
			return false;
		if (oxcmail_exchsched_compat &&
		    pmsg->proplist.set(PR_SENDER_NAME, pdisplay_name) != 0)
			return false;
	}
	if (paddress == nullptr)
		return true;
	tmp_bin.pb = tmp_buff;
	tmp_bin.cb = 0;
	if (!username_to_entryid(paddress, pdisplay_name, &tmp_bin, nullptr))
		return false;

	/*
	 * Cf. [MS-OXCICAL] v20240416 §2.1.3.1.1.20.61
	 * "property: X-MS-OLK-SENDER":
	 * Brief Description: The delegate sending the meeting on behalf of the
	 * organizer.
	 *
	 * Subsection 61 says PR_SENDER_* "SHOULD" be set based on X-MS-OLK-SENDER,
	 * but EXC2019 does not do that either, and X-MS-OLK-SENDER is only generated
	 * under peculiar circumstances (cf. doc/oxocal.rst).
	 */
	if (pmsg->proplist.set(PR_SENT_REPRESENTING_ADDRTYPE, "SMTP") != 0 ||
	    pmsg->proplist.set(PR_SENT_REPRESENTING_EMAIL_ADDRESS, paddress) != 0 ||
	    pmsg->proplist.set(PR_SENT_REPRESENTING_SMTP_ADDRESS, paddress) != 0 ||
	    pmsg->proplist.set(PR_SENT_REPRESENTING_ENTRYID, &tmp_bin) != 0)
		return false;
	if (oxcmail_exchsched_compat) {
		if (pmsg->proplist.set(PR_SENDER_ADDRTYPE, "SMTP") != 0 ||
		    pmsg->proplist.set(PR_SENDER_EMAIL_ADDRESS, paddress) != 0 ||
		    pmsg->proplist.set(PR_SENDER_SMTP_ADDRESS, paddress) != 0 ||
		    pmsg->proplist.set(PR_SENDER_ENTRYID, &tmp_bin) != 0)
			return false;
	}
	return true;
}

static bool oxcical_parse_sequence(const ical_component &main_event,
    namemap &phash, uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	auto piline = main_event.get_line("X-MICROSOFT-CDO-APPT-SEQUENCE");
	if (piline == nullptr)
		piline = main_event.get_line("SEQUENCE");
	if (piline == nullptr)
		return true;

	const char *pvalue;
	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return true;
	uint32_t tmp_int32 = strtol(pvalue, nullptr, 0);
	PROPERTY_NAME pn = {MNID_ID, PSETID_Appointment, PidLidAppointmentSequence};
	if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
		return false;
	if (pmsg->proplist.set(PROP_TAG(PT_LONG, *plast_propid), &tmp_int32) != 0)
		return false;
	(*plast_propid) ++;
	return true;
}

static constexpr std::pair<enum ol_busy_status, const char *> busy_status_names[] = {
	{olFree, "FREE"},
	{olTentative, "TENTATIVE"},
	{olBusy, "BUSY"},
	{olOutOfOffice, "OOF"},
	{olWorkingElsewhere, "WORKINGELSEWHERE"},
};

static ol_busy_status lookup_busy_by_name(const char *s)
{
	auto it = std::find_if(std::cbegin(busy_status_names), std::cend(busy_status_names),
	          [&](const auto &p) { return strcasecmp(p.second, s) == 0; });
	return it != std::cend(busy_status_names) ? it->first : olIndeterminate;
}

static ol_busy_status lookup_busy_by_name(const ical_line *l)
{
	if (l == nullptr)
		return olIndeterminate;
	auto v = l->get_first_subvalue();
	return v != nullptr ? lookup_busy_by_name(v) : olIndeterminate;
}

static ol_busy_status lookup_busy_by_transp(const ical_line *l)
{
	if (l == nullptr)
		return olIndeterminate;
	auto v = l->get_first_subvalue();
	if (v == nullptr)
		return olIndeterminate;
	if (strcasecmp(v, "TRANSPARENT") == 0)
		return olFree;
	if (strcasecmp(v, "OPAQUE") == 0)
		return olBusy;
	return olIndeterminate;
}

static ol_busy_status lookup_busy_by_status(const ical_line *l)
{
	if (l == nullptr)
		return olIndeterminate;
	auto v = l->get_first_subvalue();
	if (v == nullptr)
		return olIndeterminate;
	if (strcasecmp(v, "CANCELLED") == 0)
		return olFree;
	if (strcasecmp(v, "TENTATIVE") == 0)
		return olTentative;
	if (strcasecmp(v, "CONFIRMED") == 0)
		return olBusy;
	return olIndeterminate;
}

static bool oxcical_set_busystatus(ol_busy_status busy_status,
    uint32_t pidlid, namemap &phash, uint16_t *plast_propid,
    MESSAGE_CONTENT *pmsg, EXCEPTIONINFO *pexception)
{
	if (busy_status == olIndeterminate)
		return true;
	PROPERTY_NAME pn = {MNID_ID, PSETID_Appointment, pidlid};
	if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
		return false;
	if (pmsg->proplist.set(PROP_TAG(PT_LONG, *plast_propid), &busy_status) != 0)
		return false;
	(*plast_propid) ++;
	if (pexception != nullptr) {
		pexception->overrideflags |= ARO_BUSYSTATUS;
		pexception->busystatus = busy_status;
	}
	return true;
}

static bool oxcical_parse_summary(const ical_component &main_event,
    MESSAGE_CONTENT *pmsg, EXT_BUFFER_ALLOC alloc, EXCEPTIONINFO *pexception,
	EXTENDEDEXCEPTION *pext_exception)
{
	auto piline = main_event.get_line("SUMMARY");
	if (piline == nullptr)
		return true;
	int i;
	int tmp_len;
	const char *pvalue;
	char tmp_buff[1024];

	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return true;
	tmp_len = strlen(pvalue);
	if (tmp_len >= 1024)
		return true;
	memcpy(tmp_buff, pvalue, tmp_len + 1);
	if (!utf8_truncate(tmp_buff, 255))
		return true;
	tmp_len = strlen(tmp_buff);
	for (i=0; i<tmp_len; i++) {
		if ('\r' == tmp_buff[i] || '\n' == tmp_buff[i]) {
			memmove(tmp_buff + i, tmp_buff + i + 1, tmp_len - i);
			tmp_len --;
		}
	}
	if (pmsg->proplist.set(PR_SUBJECT, tmp_buff) != 0)
		return false;
	if (pexception != nullptr && pext_exception != nullptr) {
		pexception->overrideflags |= ARO_SUBJECT;
		pexception->subject = static_cast<char *>(alloc(tmp_len + 1));
		if (pexception->subject == nullptr)
			return false;
		strcpy(pexception->subject, tmp_buff);
		pext_exception->subject = static_cast<char *>(alloc(tmp_len + 1));
		if (pext_exception->subject == nullptr)
			return false;
		strcpy(pext_exception->subject, tmp_buff);
	}
	return true;
}

static bool oxcical_parse_ownerapptid(const ical_component &main_event,
    MESSAGE_CONTENT *pmsg)
{
	auto piline = main_event.get_line("X-MICROSOFT-CDO-OWNERAPPTID");
	if (piline == nullptr)
		return true;
	const char *pvalue;

	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return true;
	uint32_t tmp_int32 = strtol(pvalue, nullptr, 0);
	if (pmsg->proplist.set(PR_OWNER_APPT_ID, &tmp_int32) != 0)
		return false;
	return true;
}

static bool oxcical_parse_recurrence_id(const ical_component *ptz_component,
    const ical_line &piline, namemap &phash,
    uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	time_t tmp_time;
	ical_time itime{};
	uint64_t tmp_int64;

	if (!oxcical_parse_dtvalue(ptz_component,
	    piline, &itime, &tmp_time))
		return false;
	PROPERTY_NAME pn = {MNID_ID, PSETID_Appointment, PidLidExceptionReplaceTime};
	if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
		return false;
	tmp_int64 = rop_util_unix_to_nttime(tmp_time);
	if (pmsg->proplist.set(PROP_TAG(PT_SYSTIME, *plast_propid), &tmp_int64) != 0)
		return false;
	(*plast_propid) ++;
	return true;
}

static bool oxcical_parse_disallow_counter(const ical_component &main_event,
    namemap &phash, uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	auto piline = main_event.get_line("X-MICROSOFT-DISALLOW-COUNTER");
	if (piline == nullptr)
		return true;
	uint8_t tmp_byte;
	const char *pvalue;

	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return true;
	if (strcasecmp(pvalue, "TRUE") == 0)
		tmp_byte = 1;
	else if (strcasecmp(pvalue, "FALSE") == 0)
		tmp_byte = 0;
	else
		return true;

	PROPERTY_NAME pn = {MNID_ID, PSETID_Appointment, PidLidAppointmentNotAllowPropose};
	if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
		return false;
	if (pmsg->proplist.set(PROP_TAG(PT_BOOLEAN, *plast_propid), &tmp_byte) != 0)
		return false;
	(*plast_propid) ++;
	return true;
}

static uint32_t aptrecur_to_recurtype(const APPOINTMENT_RECUR_PAT &apr)
{
	switch (apr.recur_pat.recurfrequency) {
	case IDC_RCEV_PAT_ORB_DAILY:   return rectypeDaily;
	case IDC_RCEV_PAT_ORB_WEEKLY:  return rectypeWeekly;
	case IDC_RCEV_PAT_ORB_MONTHLY: return rectypeMonthly;
	case IDC_RCEV_PAT_ORB_YEARLY:  return rectypeYearly;
	default:                       return rectypeNone;
	}
}

static bool oxcical_parse_appointment_recurrence(APPOINTMENT_RECUR_PAT *apr,
    namemap &phash, uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	EXT_PUSH ext_push;

	if (!ext_push.init(nullptr, 0, EXT_FLAG_UTF16) ||
	    ext_push.p_apptrecpat(*apr) != EXT_ERR_SUCCESS)
		return false;
	tmp_bin.cb = ext_push.m_offset;
	tmp_bin.pb = ext_push.m_udata;
	PROPERTY_NAME propname = {MNID_ID, PSETID_Appointment, PidLidAppointmentRecur};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return false;
	if (pmsg->proplist.set(PROP_TAG(PT_BINARY, *plast_propid), &tmp_bin) != 0)
		return false;
	(*plast_propid) ++;
	propname = {MNID_ID, PSETID_Appointment, PidLidRecurring};
	uint8_t flag = 1;
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0 ||
	    pmsg->proplist.set(PROP_TAG(PT_BOOLEAN, *plast_propid), &flag) != 0)
		return false;
	++*plast_propid;
	propname = {MNID_ID, PSETID_Appointment, PidLidRecurrenceType};
	uint32_t num = aptrecur_to_recurtype(*apr);
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0 ||
	    pmsg->proplist.set(PROP_TAG(PT_LONG, *plast_propid), &num) != 0)
		return false;
	++*plast_propid;
	auto nt_time = rop_util_rtime_to_nttime(
		apr->recur_pat.endtype == IDC_RCEV_PAT_ERB_NOEND ||
		apr->recur_pat.endtype == IDC_RCEV_PAT_ERB_NOEND1 ?
		ENDDATE_MISSING : apr->recur_pat.enddate);
	propname = {MNID_ID, PSETID_Appointment, PidLidClipEnd};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return false;
	if (pmsg->proplist.set(PROP_TAG(PT_SYSTIME, *plast_propid), &nt_time) != 0)
		return false;
	(*plast_propid) ++;
	nt_time = rop_util_rtime_to_nttime(apr->recur_pat.startdate);
	propname = {MNID_ID, PSETID_Appointment, PidLidClipStart};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return false;
	if (pmsg->proplist.set(PROP_TAG(PT_SYSTIME, *plast_propid), &nt_time) != 0)
		return false;
	(*plast_propid) ++;
	return true;
}

static void oxcical_replace_propid(TPROPVAL_ARRAY *pproplist,
    const propididmap_t &phash)
{
	int i;
	uint16_t propid;
	uint32_t proptag;

	for (i=0; i<pproplist->count; i++) {
		proptag = pproplist->ppropval[i].proptag;
		propid = PROP_ID(proptag);
		if (!is_nameprop_id(propid))
			continue;
		auto it = phash.find(propid);
		if (it == phash.cend() || it->second == 0) {
			pproplist->erase(proptag);
			i --;
			continue;
		}
		pproplist->ppropval[i].proptag =
			PROP_TAG(PROP_TYPE(pproplist->ppropval[i].proptag), it->second);
	}
}

static bool oxcical_fetch_propname(MESSAGE_CONTENT *pmsg, namemap &phash,
    EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids) try
{
	PROPID_ARRAY propids;
	PROPID_ARRAY propids1;
	PROPNAME_ARRAY propnames;

	propnames.count = 0;
	propnames.ppropname = static_cast<PROPERTY_NAME *>(alloc(sizeof(PROPERTY_NAME) * phash.size()));
	if (propnames.ppropname == nullptr)
		return false;
	for (const auto &pair : phash) {
		propids.push_back(pair.first);
		propnames.ppropname[propnames.count++] = pair.second;
	}
	if (!get_propids(&propnames, &propids1) ||
	    propids1.size() != propnames.size())
		return false;
	propididmap_t phash1;
	for (size_t i = 0; i < propids.size(); ++i)
		phash1.emplace(propids[i], propids1[i]);
	oxcical_replace_propid(&pmsg->proplist, phash1);
	if (pmsg->children.prcpts != nullptr)
		for (auto &rcpt : *pmsg->children.prcpts)
			oxcical_replace_propid(&rcpt, phash1);
	if (pmsg->children.pattachments != nullptr)
		for (auto &at : *pmsg->children.pattachments)
			oxcical_replace_propid(&at.proplist, phash1);
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2172: ENOMEM");
	return false;
}

static bool oxcical_parse_exceptional_attachment(ATTACHMENT_CONTENT *pattachment,
    const ical_component &, ical_time start_itime, ical_time end_itime,
    message_content *pmsg)
{
	BINARY tmp_bin;
	time_t tmp_time;
	uint8_t tmp_byte;
	uint32_t tmp_int32;
	uint64_t tmp_int64;

	tmp_int32 = ATTACH_EMBEDDED_MSG;
	if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) != 0)
		return false;
	if (pattachment->proplist.set(PR_RENDERING_POSITION, &indet_rendering_pos) != 0)
		return false;
	auto newval = pattachment->pembedded->proplist.getval(PR_SUBJECT);
	if (newval != nullptr &&
	    pattachment->proplist.set(PR_DISPLAY_NAME, newval) != 0)
		return false;
	if (!ical_itime_to_utc(nullptr, start_itime, &tmp_time))
		return false;
	tmp_int64 = rop_util_unix_to_nttime(tmp_time);
	if (pattachment->proplist.set(PR_EXCEPTION_STARTTIME, &tmp_int64) != 0)
		return false;
	if (!ical_itime_to_utc(nullptr, end_itime, &tmp_time))
		return false;
	tmp_int64 = rop_util_unix_to_nttime(tmp_time);
	if (pattachment->proplist.set(PR_EXCEPTION_ENDTIME, &tmp_int64) != 0)
		return false;
	tmp_bin.cb = 0;
	tmp_bin.pb = nullptr;
	if (pattachment->proplist.set(PR_ATTACH_ENCODING, &tmp_bin) != 0)
		return false;
	tmp_int32 = afException;
	if (pattachment->proplist.set(PR_ATTACHMENT_FLAGS, &tmp_int32) != 0)
		return false;
	tmp_int32 = 0x00000000;
	if (pattachment->proplist.set(PR_ATTACHMENT_LINKID, &tmp_int32) != 0 ||
	    pattachment->proplist.set(PR_ATTACH_FLAGS, &tmp_int32) != 0)
		return false;
	tmp_byte = 1;
	if (pattachment->proplist.set(PR_ATTACHMENT_HIDDEN, &tmp_byte) != 0)
		return false;
	tmp_byte = 0;
	if (pattachment->proplist.set(PR_ATTACHMENT_CONTACTPHOTO, &tmp_byte) != 0)
		return false;
	return true;
}

static bool oxcical_parse_atx_value(const ical_line &piline,
    int count, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	uint8_t tmp_byte;
	uint32_t tmp_int32;
	uint64_t tmp_int64;
	char tmp_buff[1024];
	ATTACHMENT_LIST *pattachments;
	ATTACHMENT_CONTENT *pattachment;

	auto pvalue = piline.get_first_subvalue();
	if (pvalue == nullptr || strncasecmp(pvalue, "CID:", 4) == 0)
		return true;
	if (pmsg->children.pattachments == nullptr) {
		pattachments = attachment_list_init();
		if (pattachments == nullptr)
			return false;
		pmsg->set_attachments_internal(pattachments);
	} else {
		pattachments = pmsg->children.pattachments;
	}
	pattachment = attachment_content_init();
	if (pattachment == nullptr)
		return false;
	if (!pattachments->append_internal(pattachment)) {
		attachment_content_free(pattachment);
		return false;
	}
	tmp_bin.cb = gx_snprintf(tmp_buff, std::size(tmp_buff),
		"[InternetShortcut]\r\nURL=%s", pvalue);
	tmp_bin.pc = tmp_buff;
	if (pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin) != 0)
		return false;
	tmp_bin.cb = 0;
	tmp_bin.pb = nullptr;
	if (pattachment->proplist.set(PR_ATTACH_ENCODING, &tmp_bin) != 0)
		return false;
	if (pattachment->proplist.set(PR_ATTACH_EXTENSION, ".URL") != 0)
		return false;
	const char *pvalue1 = strrchr(pvalue, '/'); /* CONST-STRCHR-MARKER */
	if (pvalue1 == nullptr)
		pvalue1 = pvalue;
	snprintf(tmp_buff, 256, "%s.url", pvalue1);
	if (pattachment->proplist.set(PR_ATTACH_LONG_FILENAME, tmp_buff) != 0 ||
	    pattachment->proplist.set(PR_DISPLAY_NAME, tmp_buff) != 0)
		return false;
	tmp_int32 = ATTACH_BY_VALUE;
	if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) != 0)
		return false;
	pvalue1 = piline.get_first_paramval("FMTYPE");
	if (pvalue1 != nullptr &&
	    pattachment->proplist.set(PR_ATTACH_MIME_TAG, pvalue1) != 0)
		return false;
	tmp_int32 = 0;
	if (pattachment->proplist.set(PR_ATTACH_FLAGS, &tmp_int32) != 0)
		return false;
	tmp_int32 = 0;
	if (pattachment->proplist.set(PR_ATTACHMENT_LINKID, &tmp_int32) != 0)
		return false;
	tmp_byte = 0;
	if (pattachment->proplist.set(PR_ATTACHMENT_CONTACTPHOTO, &tmp_byte) != 0)
		return false;
	tmp_int64 = 0x0CB34557A3DD4000;
	if (pattachment->proplist.set(PR_EXCEPTION_STARTTIME, &tmp_int64) != 0 ||
	    pattachment->proplist.set(PR_EXCEPTION_ENDTIME, &tmp_int64) != 0)
		return false;
	if (pattachment->proplist.set(PR_RENDERING_POSITION, &indet_rendering_pos) != 0)
		return false;
	return true;
}

static bool oxcical_parse_atx_binary(const ical_line &piline,
    int count, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	size_t decode_len;
	uint8_t tmp_byte;
	uint64_t tmp_int64;
	char tmp_buff[1024];
	ATTACHMENT_LIST *pattachments;
	ATTACHMENT_CONTENT *pattachment;

	auto pvalue = piline.get_first_paramval("ENCODING");
	if (pvalue == nullptr || strcasecmp(pvalue, "BASE64") != 0)
		return false;
	if (pmsg->children.pattachments == nullptr) {
		pattachments = attachment_list_init();
		if (pattachments == nullptr)
			return false;
		pmsg->set_attachments_internal(pattachments);
	} else {
		pattachments = pmsg->children.pattachments;
	}
	pattachment = attachment_content_init();
	if (pattachment == nullptr)
		return false;
	if (!pattachments->append_internal(pattachment)) {
		attachment_content_free(pattachment);
		return false;
	}
	pvalue = piline.get_first_subvalue();
	if (pvalue != nullptr) {
		uint32_t tmp_int32 = strlen(pvalue) / 4 * 3 + 1;
		tmp_bin.pv = malloc(tmp_int32);
		if (tmp_bin.pv == nullptr)
			return false;
		if (decode64(pvalue, tmp_int32, tmp_bin.pv, tmp_int32, &decode_len) != 0) {
			free(tmp_bin.pb);
			return false;
		}
		tmp_bin.cb = decode_len;
	} else {
		tmp_bin.cb = 0;
		tmp_bin.pb = nullptr;
	}
	if (pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin) != 0)
		return false;
	if (tmp_bin.pb != nullptr)
		free(tmp_bin.pb);
	tmp_bin.cb = 0;
	tmp_bin.pb = nullptr;
	if (pattachment->proplist.set(PR_ATTACH_ENCODING, &tmp_bin) != 0)
		return false;
	pvalue = piline.get_first_paramval("X-FILENAME");
	if (pvalue == nullptr)
		pvalue = piline.get_first_paramval("FILENAME");
	if (pvalue == nullptr) {
		snprintf(tmp_buff, std::size(tmp_buff), "calendar_attachment%d.dat", count);
		pvalue = tmp_buff;
	}
	const char *pvalue1 = strrchr(pvalue, '.'); /* CONST-STRCHR-MARKER */
	if (pvalue1 == nullptr)
		pvalue1 = ".dat";
	if (pattachment->proplist.set(PR_ATTACH_EXTENSION, pvalue1) != 0 ||
	    pattachment->proplist.set(PR_ATTACH_LONG_FILENAME, pvalue) != 0 ||
	    pattachment->proplist.set(PR_DISPLAY_NAME, pvalue) != 0)
		return false;
	uint32_t tmp_int32 = ATTACH_BY_VALUE;
	if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) != 0)
		return false;
	pvalue1 = piline.get_first_paramval("FMTYPE");
	if (pvalue1 != nullptr &&
	    pattachment->proplist.set(PR_ATTACH_MIME_TAG, pvalue1) != 0)
		return false;
	tmp_int32 = 0;
	if (pattachment->proplist.set(PR_ATTACH_FLAGS, &tmp_int32) != 0 ||
	    pattachment->proplist.set(PR_ATTACHMENT_LINKID, &tmp_int32) != 0)
		return false;
	tmp_byte = 0;
	if (pattachment->proplist.set(PR_ATTACHMENT_CONTACTPHOTO, &tmp_byte) != 0)
		return false;
	tmp_int64 = 0x0CB34557A3DD4000;
	if (pattachment->proplist.set(PR_EXCEPTION_STARTTIME, &tmp_int64) != 0 ||
	    pattachment->proplist.set(PR_EXCEPTION_ENDTIME, &tmp_int64) != 0)
		return false;
	if (pattachment->proplist.set(PR_RENDERING_POSITION, &indet_rendering_pos) != 0)
		return false;
	return true;
}

static bool oxcical_parse_attachment(const ical_line &piline,
    int count, MESSAGE_CONTENT *pmsg)
{
	auto v = piline.get_first_paramval("VALUE");
	if (v == nullptr)
		return oxcical_parse_atx_value(piline, count, pmsg);
	else if (strcasecmp(v, "BINARY") == 0)
		return oxcical_parse_atx_binary(piline, count, pmsg);
	return true;
}

static bool oxcical_parse_valarm(uint32_t reminder_delta, time_t start_time,
    namemap &phash, uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	uint8_t tmp_byte;
	uint64_t tmp_int64;
	PROPERTY_NAME propname = {MNID_ID, PSETID_Common, PidLidReminderDelta};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return false;
	if (pmsg->proplist.set(PROP_TAG(PT_LONG, *plast_propid), &reminder_delta) != 0)
		return false;
	(*plast_propid) ++;
	propname.guid = PSETID_Common;
	propname.kind = MNID_ID;
	propname.lid = PidLidReminderTime;
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return false;
	tmp_int64 = rop_util_unix_to_nttime(start_time);
	if (pmsg->proplist.set(PROP_TAG(PT_SYSTIME, *plast_propid), &tmp_int64) != 0)
		return false;
	(*plast_propid) ++;
	propname = {MNID_ID, PSETID_Common, PidLidReminderSignalTime};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return false;
	tmp_int64 = rop_util_unix_to_nttime(
		start_time - reminder_delta*60);
	if (pmsg->proplist.set(PROP_TAG(PT_SYSTIME, *plast_propid), &tmp_int64) != 0)
		return false;
	(*plast_propid) ++;
	propname = {MNID_ID, PSETID_Common, PidLidReminderSet};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return false;
	tmp_byte = 1;
	if (pmsg->proplist.set(PROP_TAG(PT_BOOLEAN, *plast_propid), &tmp_byte) != 0)
		return false;
	(*plast_propid) ++;
	return true;
}

static const ical_component *oxcical_main_event(const event_list_t &evlist, const char **err)
{
	*err = nullptr;
	if (evlist.size() == 1)
		return evlist.front();
	const ical_component *main_event = nullptr;
	for (const auto &event : evlist) {
		auto line = event->get_line("RECURRENCE-ID");
		if (line != nullptr) {
			if (event->get_line("X-MICROSOFT-RRULE") != nullptr ||
			    event->get_line("RRULE") != nullptr) {
				*err = "E-2736: Instance within recurrence set has no RRULE line";
				return nullptr;
			}
			continue;
		}
		if (main_event != nullptr) {
			*err = "E-2737: There is more than one \"main\" event in this calendar object";
			return nullptr;
		}
		main_event = event;
		if (main_event->get_line("X-MICROSOFT-RRULE") == nullptr &&
		    main_event->get_line("RRULE") == nullptr) {
			*err = "E-2738: Main VEVENT in this calendar object has no RRULE line";
			return nullptr;
		}
	}
	return main_event;
}

static bool oxcical_parse_allday(const ical_component &main_ev)
{
	auto line = main_ev.get_line("X-MICROSOFT-MSNCALENDAR-ALLDAYEVENT");
	if (line == nullptr)
		line = main_ev.get_line("X-MICROSOFT-CDO-ALLDAYEVENT");
	if (line == nullptr)
		return false;
	auto v = line->get_first_subvalue();
	return v != nullptr && strcasecmp(v, "true") == 0;
}

static bool oxcical_parse_importance(const ical_component &main_event,
    MESSAGE_CONTENT *msg)
{
	auto line = main_event.get_line("X-MICROSOFT-CDO-IMPORTANCE");
	if (line == nullptr)
		line = main_event.get_line("X-MICROSOFT-MSNCALENDAR-IMPORTANCE");
	if (line != nullptr) {
		auto str = line->get_first_subvalue();
		if (str == nullptr)
			return true;
		uint32_t imp = strtol(str, nullptr, 0);
		if (imp <= IMPORTANCE_HIGH &&
		    msg->proplist.set(PR_IMPORTANCE, &imp) != 0)
			return false;
		return true;
	}
	line = main_event.get_line("PRIORITY");
	if (line == nullptr)
		return true;
	auto str = line->get_first_subvalue();
	if (str == nullptr)
		return true;
	/*
	 * RFC 5545 §3.8.1.9 / MS-OXCICAL v13 §2.1.3.1.1.20.17 pg 58.
	 * (Decidedly different from OXCMAIL's X-Priority.)
	 */
	auto v = strtol(str, nullptr, 0);
	uint32_t imp;
	if (v >= 1 && v <= 4)
		imp = IMPORTANCE_HIGH;
	else if (v == 5)
		imp = IMPORTANCE_NORMAL;
	else if (v >= 6 && v <= 9)
		imp = IMPORTANCE_LOW;
	else
		return true;
	return msg->proplist.set(PR_IMPORTANCE, &imp) == 0;
}

static inline unsigned int dfl_alarm_offset(bool allday)
{
	return allday ? 1080 : 15;
}

static const char *oxcical_import_internal(const char *str_zone, const char *method,
    bool b_proposal, uint16_t calendartype, const ical &pical,
    const event_list_t &pevent_list, EXT_BUFFER_ALLOC alloc,
    GET_PROPIDS get_propids, USERNAME_TO_ENTRYID username_to_entryid,
    message_content *pmsg, ical_time *pstart_itime, ical_time *pend_itime,
    EXCEPTIONINFO *pexception, EXTENDEDEXCEPTION *pext_exception)
{
	const char *mev_error;
	auto pmain_event = oxcical_main_event(pevent_list, &mev_error);
	if (pmain_event == nullptr)
		return znul(mev_error);
	if (pexception != nullptr && pext_exception != nullptr) {
		memset(pexception, 0, sizeof(EXCEPTIONINFO));
		memset(pext_exception, 0, sizeof(EXTENDEDEXCEPTION));
		pext_exception->changehighlight.size = sizeof(uint32_t);
	}
	if (!oxcical_parse_recipients(*pmain_event, username_to_entryid, pmsg))
		return "E-2189: oxcical_import: parse_recipients returned an unspecified error";
	uint16_t last_propid = 0x8000;
	namemap phash;
	if (b_proposal && !oxcical_parse_proposal(phash, &last_propid, pmsg))
		return "E-2190: oxcical_parse_proposal returned an unspecified error";
	if (!oxcical_parse_categories(*pmain_event, phash, &last_propid, pmsg))
		return "E-2191: oxcical_parse_categories returned an unspecified error";
	if (!oxcical_parse_class(*pmain_event, pmsg))
		return "E-2192: oxcical_parse_class returned an unspecified error";
	if (!oxcical_parse_body(*pmain_event, method, pmsg))
		return "E-2705: oxcical_parse_body returned an unspecified error";
	if (!oxcical_parse_html(*pmain_event, pmsg))
		return "E-2193: oxcical_parse_html returned an unspecified error";
	bool b_allday = oxcical_parse_allday(*pmain_event);
	if (!oxcical_parse_dtstamp(*pmain_event, method,
	    phash, &last_propid, pmsg))
		return "E-2194: oxcical_parse_dtstamp returned an unspecified error";

	auto piline = pmain_event->get_line("DTSTART");
	if (piline == nullptr)
		return "E-2741: oxcical_import_internal: no DTSTART";
	auto pvalue1 = piline->get_first_paramval("VALUE");
	auto ptzid = piline->get_first_paramval("TZID");
	const ical_component *ptz_component = nullptr;
	if (ptzid != nullptr) {
		ptz_component = oxcical_find_vtimezone(pical, ptzid);
		if (ptz_component == nullptr) {
			mlog(LV_ERR, "E-2070: %s: timezone \"%s\" not found", __func__, znul(ptzid));
			return "Used timezone was not declared";
		}
		if (!oxcical_parse_tzdisplay(true, *ptz_component, phash,
		    &last_propid, pmsg))
			return "E-2195: oxcical_parse_tzdisplay returned an unspecified error";
	}

	time_t start_time = 0, end_time = 0;
	ical_time start_itime{}, end_itime{};
	/*
	 * EXC2019 treats iCalendar floating time as if it was specified with
	 * UTC time. As a result, export of such MAPI objects can shift it.
	 */
	if (!oxcical_parse_dtvalue(ptz_component,
	    *piline, &start_itime, &start_time))
		return "E-2196: oxcical_parse_dtvalue returned an unspecified error";
	if (!oxcical_parse_start_end(true, b_proposal,
	    *pmain_event, start_time, phash, &last_propid, pmsg))
		return "E-2197: oxcical_parse_start_end returned an unspecified error";
	if (pstart_itime != nullptr)
		*pstart_itime = start_itime;

	piline = pmain_event->get_line("DTEND");
	if (piline != nullptr) {
		auto pvalue = piline->get_first_paramval("TZID");
		bool parse_dtv = (pvalue == nullptr && ptzid == nullptr) ||
		                 (pvalue != nullptr && ptzid != nullptr &&
		                 strcasecmp(pvalue, ptzid) == 0);
		if (!parse_dtv)
			return "E-2199: oxcical_import: TZID present but VTIMEZONE not (or vice-versa)";
		if (!oxcical_parse_dtvalue(ptz_component,
		    *piline, &end_itime, &end_time))
			return "E-2198: oxcical_parse_dtvalue returned an unspecified error";
		if (end_time < start_time)
			return "E-2795: ical not imported due to end_time < start_time";
	} else {
		piline = pmain_event->get_line("DURATION");
		if (piline == nullptr) {
			end_itime = start_itime;
			if (pvalue1 != nullptr && strcasecmp(pvalue1, "DATE") == 0) {
				end_itime.hour = 0;
				end_itime.minute = 0;
				end_itime.second = 0;
				end_itime.leap_second = 0;
				end_itime.add_day(1);
			}
			ical_itime_to_utc(ptz_component, end_itime, &end_time);
		} else {
			long duration;
			auto pvalue = piline->get_first_subvalue();
			if (pvalue == nullptr ||
			    !ical_parse_duration(pvalue, &duration) || duration < 0)
				return "E-2700: ical_parse_duration returned an unspecified error";
			end_itime = start_itime;
			end_time = start_time + duration;
			end_itime.add_second(duration);
		}
	}

	if (pend_itime != nullptr)
		*pend_itime = end_itime;
	if (ptz_component != nullptr && !oxcical_parse_tzdisplay(false,
	    *ptz_component, phash, &last_propid, pmsg))
		return "E-2701: oxcical_parse_tzdisplay returned an unspecified error";
	if (!oxcical_parse_start_end(false, b_proposal,
	    *pmain_event, end_time, phash, &last_propid, pmsg))
		return "E-2702: oxcical_parse_start_end returned an unspecified error";
	uint32_t duration_min = (end_time - start_time) / 60;
	if (!oxcical_parse_duration(duration_min, phash, &last_propid, pmsg))
		return "E-2703: oxcical_parse_duration returned an unspecified error";

	if (!b_allday && start_itime.type != ICT_UTC &&
	    start_itime.type != ICT_UTC && start_itime.hour == 0 &&
	    start_itime.minute == 0 && start_itime.second == 0 &&
	    end_itime.hour == 0 && end_itime.minute == 0 &&
	    end_itime.second == 0 && end_itime.delta_day(start_itime) == 1)
		b_allday = true;
	if (b_allday && !oxcical_parse_subtype(phash, &last_propid, pmsg, pexception))
		return "E-2704: oxcical_parse_subtype returned an unspecified error";

	ical_time itime{};
	piline = pmain_event->get_line("RECURRENCE-ID");
	if (piline != nullptr) {
		if (pexception != nullptr && pext_exception != nullptr &&
		    !oxcical_parse_recurrence_id(ptz_component, *piline,
		    phash, &last_propid, pmsg))
			return "E-2706: oxcical_parse_duration returned an unspecified error";
		auto pvalue = piline->get_first_paramval("TZID");
		if (pvalue != nullptr && ptzid != nullptr &&
		    strcasecmp(pvalue, ptzid) != 0)
			return "E-2707: Timezone mismatch on RECURRENCE-ID and TZID";
		if (pvalue != nullptr) {
			if (!oxcical_parse_dtvalue(ptz_component,
			    *piline, &itime, nullptr))
				return "E-2708";
		} else {
			if (!oxcical_parse_dtvalue(nullptr,
			    *piline, &itime, nullptr))
				return "E-2709";
			if (itime.type != ICT_UTC &&
			    (itime.hour != 0 || itime.minute != 0 ||
			    itime.second != 0 || itime.leap_second != 0))
				return "E-2710";
		}
	}

	if (!oxcical_parse_uid(*pmain_event, itime, alloc,
	    phash, &last_propid, pmsg) ||
	    !oxcical_parse_location(*pmain_event, phash, &last_propid, alloc,
	    pmsg, pexception, pext_exception) ||
	    !oxcical_parse_organizer(*pmain_event, username_to_entryid, pmsg) ||
	    !oxcical_parse_importance(*pmain_event, pmsg))
		return "E-2711";
	if (!pmsg->proplist.has(PR_IMPORTANCE)) {
		int32_t tmp_int32 = IMPORTANCE_NORMAL;
		if (pmsg->proplist.set(PR_IMPORTANCE, &tmp_int32) != 0)
			return "E-2712";
	}
	if (!oxcical_parse_sequence(*pmain_event, phash, &last_propid, pmsg))
		return "E-2713";

	piline = pmain_event->get_line("X-MICROSOFT-CDO-BUSYSTATUS");
	if (piline == nullptr)
		piline = pmain_event->get_line("X-MICROSOFT-MSNCALENDAR-BUSYSTATUS");
	auto busy_status = lookup_busy_by_name(piline);
	piline = pmain_event->get_line("X-MICROSOFT-CDO-INTENDEDSTATUS");
	if (piline == nullptr)
		piline = pmain_event->get_line("X-MICROSOFT-MSNCALENDAR-INTENDEDSTATUS");
	auto intent_status = lookup_busy_by_name(piline);
	if (method != nullptr && strcasecmp(method, "REQUEST") == 0) {
		/* OXCICAL v11 pg 73 */
		if (intent_status == olIndeterminate) {
			intent_status = busy_status;
			if (intent_status == olIndeterminate) {
				intent_status = olBusy;
				busy_status = olTentative;
			}
		}
	}
	if (busy_status == olIndeterminate)
		busy_status = lookup_busy_by_transp(pmain_event->get_line("TRANSP"));
	if (busy_status == olIndeterminate)
		busy_status = lookup_busy_by_status(pmain_event->get_line("STATUS"));
	/*
	 * N.B.: This edits the MAPI message destined for the Inbox folder; it is not
	 * editing the Calendar folder MAPI message (this does not exist yet).
	 */
	if (!oxcical_set_busystatus(busy_status, PidLidBusyStatus, phash,
	    &last_propid, pmsg, pexception))
		return "E-2714";
	if (!oxcical_set_busystatus(intent_status, PidLidIntendedBusyStatus, phash,
	    &last_propid, pmsg, nullptr))
		return "E-2715";

	if (!oxcical_parse_ownerapptid(*pmain_event, pmsg) ||
	    !oxcical_parse_disallow_counter(*pmain_event, phash,
	    &last_propid, pmsg) ||
	    !oxcical_parse_summary(*pmain_event, pmsg, alloc,
	    pexception, pext_exception))
		return "E-2716";

	piline = pmain_event->get_line("RRULE");
	if (piline == nullptr)
		piline = pmain_event->get_line("X-MICROSOFT-RRULE");
	if (piline != nullptr) {
		if (ptz_component != nullptr &&
		    !oxcical_parse_recurring_timezone(*ptz_component,
		    phash, &last_propid, pmsg))
			return "E-2717";

		uint32_t deleted_dates[1024], modified_dates[1024];
		EXCEPTIONINFO exceptions[1024];
		EXTENDEDEXCEPTION ext_exceptions[1024];
		APPOINTMENT_RECUR_PAT apr{};

		apr.recur_pat.deletedinstancecount = 0;
		apr.recur_pat.pdeletedinstancedates = deleted_dates;
		apr.recur_pat.modifiedinstancecount = 0;
		apr.recur_pat.pmodifiedinstancedates = modified_dates;
		apr.exceptioncount = 0;
		apr.pexceptioninfo = exceptions;
		apr.pextendedexception = ext_exceptions;
		if (!oxcical_parse_rrule(*ptz_component, *piline, calendartype,
		    start_time, duration_min, &apr))
			return "E-2718";
		piline = pmain_event->get_line("EXDATE");
		if (piline == nullptr)
			piline = pmain_event->get_line("X-MICROSOFT-EXDATE");
		if (piline != nullptr && !oxcical_parse_dates(ptz_component,
		    *piline, &apr.recur_pat.deletedinstancecount, deleted_dates))
			return "E-2719";
		piline = pmain_event->get_line("RDATE");
		if (piline != nullptr) {
			if (!oxcical_parse_dates(ptz_component, *piline,
			    &apr.recur_pat.modifiedinstancecount, modified_dates))
				return "E-2720";
			if (apr.recur_pat.modifiedinstancecount < apr.recur_pat.deletedinstancecount)
				return "E-2721";
			apr.exceptioncount = apr.recur_pat.modifiedinstancecount;
			for (size_t i = 0; i < apr.exceptioncount; ++i) {
				memset(exceptions + i, 0, sizeof(EXCEPTIONINFO));
				memset(ext_exceptions + i, 0, sizeof(EXTENDEDEXCEPTION));
				ext_exceptions[i].startdatetime = exceptions[i].startdatetime = modified_dates[i];
				ext_exceptions[i].enddatetime = exceptions[i].enddatetime = modified_dates[i] + (end_time - start_time)/60;
				ext_exceptions[i].originalstartdate = exceptions[i].originalstartdate = deleted_dates[i];
				exceptions[i].overrideflags = 0;
				ext_exceptions[i].changehighlight.size = sizeof(uint32_t);
			}
		} else {
			apr.exceptioncount = 0;
		}

		ATTACHMENT_LIST *pattachments = nullptr;
		if (pevent_list.size() > 1) {
			pattachments = attachment_list_init();
			if (pattachments == nullptr)
				return "E-2722";
			pmsg->set_attachments_internal(pattachments);
		}
		for (auto event : pevent_list) {
			if (event == pmain_event)
				continue;
			auto pattachment = attachment_content_init();
			if (pattachment == nullptr)
				return "E-2723: ENOMEM";
			if (!pattachments->append_internal(pattachment)) {
				attachment_content_free(pattachment);
				return "E-2724";
			}
			auto pembedded = message_content_init();
			if (pembedded == nullptr)
				return "E-2725";
			pattachment->set_embedded_internal(pembedded);
			if (pembedded->proplist.set(PR_MESSAGE_CLASS, "IPM.OLE.CLASS.{00061055-0000-0000-C000-000000000046}") != 0)
				return "E-2726";

			event_list_t tmp_list;
			try {
				tmp_list.push_back(event);
			} catch (...) {
				return "E-2727: ENOMEM";
			}
			mev_error = oxcical_import_internal(str_zone, method,
			            false, calendartype, pical, tmp_list, alloc,
			            get_propids, username_to_entryid, pembedded,
			            &start_itime, &end_itime,
			            exceptions + apr.exceptioncount,
			            ext_exceptions + apr.exceptioncount);
			if (mev_error != nullptr)
				return mev_error;
			if (!oxcical_parse_exceptional_attachment(pattachment,
			    *event, start_itime, end_itime, pmsg))
				return "E-2729";

			piline = event->get_line("RECURRENCE-ID");
			time_t tmp_time;
			if (!oxcical_parse_dtvalue(ptz_component,
			    *piline, &itime, &tmp_time))
				return "E-2730";
			auto minutes = rop_util_unix_to_rtime(tmp_time);
			size_t i;
			for (i = 0; i < apr.recur_pat.deletedinstancecount; ++i)
				if (deleted_dates[i] == minutes)
					break;
			if (i < apr.recur_pat.deletedinstancecount)
				continue;
			deleted_dates[apr.recur_pat.deletedinstancecount++] = minutes;
			if (apr.recur_pat.deletedinstancecount >= 1024)
				return "E-2731";
			exceptions[apr.exceptioncount].originalstartdate = minutes;
			ext_exceptions[apr.exceptioncount].originalstartdate = minutes;
			ical_itime_to_utc(nullptr, start_itime, &tmp_time);
			minutes = rop_util_unix_to_rtime(tmp_time);
			modified_dates[apr.recur_pat.modifiedinstancecount++] = minutes;
			exceptions[apr.exceptioncount].startdatetime = minutes;
			ext_exceptions[apr.exceptioncount].startdatetime = minutes;
			ical_itime_to_utc(nullptr, end_itime, &tmp_time);
			minutes = rop_util_unix_to_rtime(tmp_time);
			exceptions[apr.exceptioncount].enddatetime = minutes;
			ext_exceptions[apr.exceptioncount].enddatetime = minutes;
			++apr.exceptioncount;
		}
		std::sort(deleted_dates, deleted_dates + apr.recur_pat.deletedinstancecount);
		std::sort(modified_dates, modified_dates + apr.recur_pat.modifiedinstancecount);
		std::sort(exceptions, exceptions + apr.exceptioncount);
		std::sort(ext_exceptions, ext_exceptions + apr.exceptioncount);
		if (!oxcical_parse_appointment_recurrence(&apr, phash,
		    &last_propid, pmsg))
			return "E-2732";
	}

	size_t tmp_count = 0;
	for (const auto &line : pmain_event->line_list) {
		if (strcasecmp(line.m_name.c_str(), "ATTACH") != 0)
			continue;
		tmp_count ++;
		if (!oxcical_parse_attachment(line, tmp_count, pmsg))
			return "E-2733";
	}

	bool b_alarm = false;
	uint32_t alarmdelta = 0;
	if (pmain_event->component_list.size() > 0) {
		auto palarm_component = &pmain_event->component_list.front();
		if (strcasecmp(palarm_component->m_name.c_str(), "VALARM") == 0) {
			b_alarm = true;
			piline = palarm_component->get_line("TRIGGER");
			const char *pvalue = nullptr;
			if (piline == nullptr ||
			    (pvalue = piline->get_first_subvalue()) == nullptr) {
				alarmdelta = dfl_alarm_offset(b_allday);
			} else {
				pvalue1 = piline->get_first_paramval("RELATED");
				if (pvalue1 == nullptr) {
					time_t tmp_time;
					pvalue1 = piline->get_first_paramval("VALUE");
					alarmdelta = (pvalue1 == nullptr || strcasecmp(pvalue1, "DATE-TIME") == 0) &&
					            ical_datetime_to_utc(ptz_component, pvalue, &tmp_time) ?
					            llabs(start_time - tmp_time) / 60 :
					            dfl_alarm_offset(b_allday);
				} else {
					long duration;
					alarmdelta = strcasecmp(pvalue1, "START") == 0 &&
					            ical_parse_duration(pvalue, &duration) ?
					            labs(duration) / 60 :
					            dfl_alarm_offset(b_allday);
				}
			}
			if (!oxcical_parse_valarm(alarmdelta, start_time,
			    phash, &last_propid, pmsg))
				return "E-2734";
		}
	}

	if (pexception != nullptr) {
		if (!b_alarm) {
			pexception->overrideflags |= ARO_REMINDER;
			pexception->reminderset = 0;
		} else {
			pexception->overrideflags |= ARO_REMINDERDELTA;
			pexception->reminderdelta = alarmdelta;
		}
	}
	if (!oxcical_fetch_propname(pmsg, phash, alloc, std::move(get_propids)))
		return "E-2735";
	return nullptr;
}

static bool oxcical_import_events(const char *str_zone, uint16_t calendartype,
    const ical &pical, const uidxevent_list_t &uid_list, EXT_BUFFER_ALLOC alloc,
    GET_PROPIDS get_propids, USERNAME_TO_ENTRYID username_to_entryid,
    std::vector<message_ptr> &msgvec)
{
	for (const auto &listentry : uid_list) {
		auto &event_list = listentry.second;
		message_ptr msg(message_content_init());
		if (msg == nullptr)
			return false;
		msgvec.push_back(std::move(msg));
		auto pembedded = msgvec.back().get();
		if (pembedded->proplist.set(PR_MESSAGE_CLASS, "IPM.Appointment") != 0)
			return false;
		auto err = oxcical_import_internal(str_zone, "PUBLISH", false,
		           calendartype, pical, event_list, alloc, get_propids,
		           username_to_entryid, pembedded, nullptr, nullptr,
		           nullptr, nullptr);
		if (err != nullptr) {
			mlog(LV_ERR, "%s", err);
			return false;
		}
	}
	return true;
}

/**
 * Build a by-UID lookup map for @pical.
 *
 * Any subsequent change to pical->component_list invalidates all entries of
 * @ul. (The caller should ensure that the uidxevent_list_t object does not
 * outlive a const ICAL *pointer.)
 */
static bool oxcical_classify_calendar(const ical &pical, uidxevent_list_t &ul) try
{
	for (const auto &comp : pical.component_list) {
		auto pcomponent = &comp;
		if (strcasecmp(pcomponent->m_name.c_str(), "VEVENT") != 0)
			continue;
		auto piline = pcomponent->get_line("UID");
		auto puid = piline != nullptr ? piline->get_first_subvalue() : nullptr;
		if (puid != nullptr)
			ul[puid].push_back(pcomponent);
	}
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2053: ENOMEM");
	return false;
}

static const char *oxcical_get_partstat(const uidxevent_list_t &uid_list)
{
	if (uid_list.size() == 0)
		return nullptr;
	for (const auto &event : uid_list.cbegin()->second) {
		auto piline = event->get_line("ATTENDEE");
		if (piline != nullptr)
			return piline->get_first_paramval("PARTSTAT");
	}
	return nullptr;
}

static constexpr std::pair<enum calendar_scale, const char *> cal_scale_names[] = {
	/* keep ordered by CAL value */
	{CAL_GREGORIAN, "Gregorian"},
	{CAL_GREGORIAN_US, "Gregorian_us"},
	{CAL_JAPAN, "Japan"},
	{CAL_TAIWAN, "Taiwan"},
	{CAL_KOREA, "Korea"},
	{CAL_HIJRI, "Hijri"},
	{CAL_THAI, "Thai"},
	{CAL_HEBREW, "Hebrew"},
	{CAL_GREGORIAN_ME_FRENCH, "GregorianMeFrench"},
	{CAL_GREGORIAN_ARABIC, "GregorianArabic"},
	{CAL_GREGORIAN_XLIT_ENGLISH, "GregorianXlitEnglish"},
	{CAL_GREGORIAN_XLIT_FRENCH, "GregorianXlitFrench"},
	{CAL_LUNAR_JAPANESE, "JapanLunar"},
	{CAL_CHINESE_LUNAR, "ChineseLunar"},
	{CAL_SAKA, "Saka"},
	{CAL_LUNAR_ETO_CHN, "LunarEtoChn"},
	{CAL_LUNAR_ETO_KOR, "LunarEtoKor"},
	{CAL_LUNAR_ETO_ROKUYOU, "LunarRokuyou"},
	{CAL_LUNAR_KOREAN, "KoreaLunar"},
	{CAL_UMALQURA, "Umalqura"},
};

static uint32_t oxcical_get_calendartype(const ical_line *piline)
{
	const char *pvalue;

	if (piline == nullptr)
		return CAL_DEFAULT;
	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return CAL_DEFAULT;
	auto it = std::find_if(cal_scale_names, std::end(cal_scale_names),
	          [&](const auto &p) { return strcasecmp(pvalue, p.second) == 0; });
	return it != std::end(cal_scale_names) ? it->first : CAL_DEFAULT;
}

/**
 * Read a bunch of VCALENDAR/VEVENT items from @pical and put each of them as
 * messages into @finalvec.
 */
ec_error_t oxcical_import_multi(const char *str_zone, const ical &pical,
    EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
    USERNAME_TO_ENTRYID username_to_entryid, std::vector<message_ptr> &finalvec)
{
	bool b_proposal;
	const char *pvalue = nullptr, *pvalue1 = nullptr;

	b_proposal = false;
	auto piline = pical.get_line("X-MICROSOFT-CALSCALE");
	uint16_t calendartype = oxcical_get_calendartype(piline);
	auto mclass = "IPM.Appointment";
	std::vector<message_ptr> msgvec;
	uidxevent_list_t uid_list;
	if (!oxcical_classify_calendar(pical, uid_list) ||
	    uid_list.size() == 0) {
		mlog(LV_ERR, "E-2412: iCal import data contained no VEVENTs with UIDs");
		return ecNotFound;
	}
	piline = pical.get_line("METHOD");
	if (piline == nullptr) {
		if (!oxcical_import_events(str_zone, calendartype,
		    pical, uid_list, alloc, get_propids,
		    username_to_entryid, msgvec))
			return ecError;
		finalvec.insert(finalvec.end(), std::make_move_iterator(msgvec.begin()), std::make_move_iterator(msgvec.end()));
		return ecSuccess;
	}

	pvalue = piline->get_first_subvalue();
	if (pvalue != nullptr) {
		if (strcasecmp(pvalue, "PUBLISH") == 0) {
			if (uid_list.size() > 1) {
				if (!oxcical_import_events(str_zone,
				    calendartype, pical,
				    uid_list, alloc, get_propids,
				    username_to_entryid, msgvec))
					return ecError;
				finalvec.insert(finalvec.end(), std::make_move_iterator(msgvec.begin()), std::make_move_iterator(msgvec.end()));
				return ecSuccess;
			}
			mclass = "IPM.Appointment";
		} else if (strcasecmp(pvalue, "REQUEST") == 0) {
			if (uid_list.size() != 1)
				return ecNotFound;
			mclass = "IPM.Schedule.Meeting.Request";
		} else if (strcasecmp(pvalue, "REPLY") == 0) {
			if (uid_list.size() != 1)
				return ecNotFound;
			pvalue1 = oxcical_get_partstat(uid_list);
			if (pvalue1 != nullptr) {
				if (strcasecmp(pvalue1, "ACCEPTED") == 0)
					mclass = "IPM.Schedule.Meeting.Resp.Pos";
				else if (strcasecmp(pvalue1, "TENTATIVE") == 0)
					mclass = "IPM.Schedule.Meeting.Resp.Tent";
				else if (strcasecmp(pvalue1, "DECLINED") == 0)
					mclass = "IPM.Schedule.Meeting.Resp.Neg";
			}
		} else if (strcasecmp(pvalue, "COUNTER") == 0) {
			if (uid_list.size() != 1)
				return ecNotFound;
			pvalue1 = oxcical_get_partstat(uid_list);
			if (pvalue1 != nullptr && strcasecmp(pvalue1, "TENTATIVE") == 0) {
				mclass = "IPM.Schedule.Meeting.Resp.Tent";
				b_proposal = true;
			}
		} else if (strcasecmp(pvalue, "CANCEL") == 0) {
			mclass = "IPM.Schedule.Meeting.Canceled";
		}
	}

	message_ptr msg(message_content_init());
	if (msg == nullptr)
		return ecMAPIOOM;
	msgvec.push_back(std::move(msg));
	auto pmsg = msgvec.back().get();
	if (pmsg->proplist.set(PR_MESSAGE_CLASS, mclass) != 0)
		return ecError;
	auto err = oxcical_import_internal(str_zone, pvalue, b_proposal,
	           calendartype, pical, uid_list.begin()->second, alloc,
	           std::move(get_propids), username_to_entryid, pmsg,
	           nullptr, nullptr, nullptr, nullptr);
	if (err != nullptr) {
		mlog(LV_ERR, "%s", err);
		return ecError;
	}
	finalvec.insert(finalvec.end(), std::make_move_iterator(msgvec.begin()), std::make_move_iterator(msgvec.end()));
	return ecSuccess;
}

/**
 * Reads one VCALENDAR/VEVENT item from @pical and turns it into a
 * message_content object (IPM.Appointment or otherwise).
 *
 * If @pical, contrary to expectations, has more than one VCALENDAR/VEVENT
 * item, the message_content object will be a blank IPM.Note with embedded
 * message attachments (IPM.Appointment).
 */
message_ptr oxcical_import_single(const char *str_zone,
    const ical &pical, EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
    USERNAME_TO_ENTRYID username_to_entryid)
{
	std::vector<message_ptr> vec;
	if (oxcical_import_multi(str_zone, pical, alloc, std::move(get_propids),
	    username_to_entryid, vec) != ecSuccess || vec.size() == 0)
		return nullptr;
	if (vec.size() == 1)
		return std::move(vec.front());
	message_ptr cmsg(message_content_init());
	if (cmsg == nullptr)
		return nullptr;
	auto atlist = attachment_list_init();
	if (atlist == nullptr)
		return nullptr;
	cmsg->set_attachments_internal(atlist);
	for (auto &&emb : vec) {
		auto at = attachment_content_init();
		if (at == nullptr)
			return nullptr;
		if (!atlist->append_internal(at)) {
			attachment_content_free(at);
			return nullptr;
		}
		at->set_embedded_internal(emb.release());
	}
	return cmsg;
}

static int sprintf_dt(char *b, size_t z, const ical_time &t)
{
	return snprintf(b, z, fmt_date, t.year, t.month, t.day);
}

static int sprintf_dtlcl(char *b, size_t z, const ical_time &t)
{
	return snprintf(b, z, fmt_datetimelcl, t.year, t.month, t.day, t.hour,
	       t.minute, t.second);
}

static int sprintf_dtutc(char *b, size_t z, const ical_time &t)
{
	return snprintf(b, z, fmt_datetimeutc, t.year, t.month, t.day, t.hour,
	       t.minute, t.second);
}

static ical_component *oxcical_export_timezone(ical &pical,
    int year, const char *tzid, TIMEZONESTRUCT *ptzstruct) try
{
	int day;
	int order;
	char tmp_buff[1024];

	auto pcomponent = &pical.append_comp("VTIMEZONE");
	pcomponent->append_line("TZID", tzid);
	/* STANDARD component */
	auto pcomponent1 = &pcomponent->append_comp("STANDARD");
	order = ptzstruct->standarddate.day;
	if (order == 5)
		order = -1;
	if (0 == ptzstruct->daylightdate.month) {
		strcpy(tmp_buff, "16010101T000000");
	} else if (ptzstruct->standarddate.year == 0) {
		day = ical_get_dayofmonth(year,
			ptzstruct->standarddate.month, order,
			ptzstruct->standarddate.dayofweek);
		snprintf(tmp_buff, std::size(tmp_buff), fmt_datetimelcl,
			year, (int)ptzstruct->standarddate.month,
			day, (int)ptzstruct->standarddate.hour,
			(int)ptzstruct->standarddate.minute,
			(int)ptzstruct->standarddate.second);
	} else if (1 == ptzstruct->standarddate.year) {
		snprintf(tmp_buff, std::size(tmp_buff), fmt_datetimelcl,
			year, (int)ptzstruct->standarddate.month,
			(int)ptzstruct->standarddate.day,
			(int)ptzstruct->standarddate.hour,
			(int)ptzstruct->standarddate.minute,
			(int)ptzstruct->standarddate.second);
	} else {
		return nullptr;
	}
	pcomponent1->append_line("DTSTART", tmp_buff);
	if (0 != ptzstruct->daylightdate.month) {
		if (0 == ptzstruct->standarddate.year) {
			auto piline = &pcomponent1->append_line("RRULE");
			piline->append_value("FREQ", "YEARLY");
			auto dow = weekday_to_str(ptzstruct->standarddate.dayofweek);
			if (dow == nullptr)
				return nullptr;
			snprintf(tmp_buff, std::size(tmp_buff), "%d%s", order, dow);
			piline->append_value("BYDAY", tmp_buff);
			piline->append_value("BYMONTH", std::to_string(ptzstruct->standarddate.month));
		} else if (1 == ptzstruct->standarddate.year) {
			auto piline = &pcomponent1->append_line("RRULE");
			piline->append_value("FREQ", "YEARLY");
			piline->append_value("BYMONTHDAY", std::to_string(ptzstruct->standarddate.day));
			piline->append_value("BYMONTH", std::to_string(ptzstruct->standarddate.month));
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
	order = ptzstruct->daylightdate.day;
	if (order == 5)
		order = -1;
	if (0 == ptzstruct->daylightdate.year) {
		day = ical_get_dayofmonth(year,
			ptzstruct->daylightdate.month, order,
			ptzstruct->daylightdate.dayofweek);
		snprintf(tmp_buff, std::size(tmp_buff), fmt_datetimelcl,
			year, (int)ptzstruct->daylightdate.month,
			day, (int)ptzstruct->daylightdate.hour,
			(int)ptzstruct->daylightdate.minute,
			(int)ptzstruct->daylightdate.second);
	} else if (1 == ptzstruct->daylightdate.year) {
		snprintf(tmp_buff, std::size(tmp_buff), fmt_datetimelcl,
			year, (int)ptzstruct->daylightdate.month,
			(int)ptzstruct->daylightdate.day,
			(int)ptzstruct->daylightdate.hour,
			(int)ptzstruct->daylightdate.minute,
			(int)ptzstruct->daylightdate.second);
	} else {
		return nullptr;
	}
	pcomponent1->append_line("DTSTART", tmp_buff);
	if (0 == ptzstruct->daylightdate.year) {
		auto piline = &pcomponent1->append_line("RRULE");
		piline->append_value("FREQ", "YEARLY");
		auto dow = weekday_to_str(ptzstruct->daylightdate.dayofweek);
		if (dow == nullptr)
			return nullptr;
		snprintf(tmp_buff, std::size(tmp_buff), "%d%s", order, dow);
		piline->append_value("BYDAY", tmp_buff);
		piline->append_value("BYMONTH", std::to_string(ptzstruct->daylightdate.month));
	} else if (1 == ptzstruct->daylightdate.year) {
		auto piline = &pcomponent1->append_line("RRULE");
		piline->append_value("FREQ", "YEARLY");
		piline->append_value("BYMONTHDAY", std::to_string(ptzstruct->daylightdate.day));
		piline->append_value("BYMONTH", std::to_string(ptzstruct->daylightdate.month));
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
	mlog(LV_ERR, "E-2180: ENOMEM");
	return nullptr;
}

static bool is_meeting_response(const char *s)
{
	return class_match_prefix(s, "IPM.Schedule.Meeting.Resp.Pos") == 0 ||
	       class_match_prefix(s, "IPM.Schedule.Meeting.Resp.Neg") == 0 ||
	       class_match_prefix(s, "IPM.Schedule.Meeting.Resp.Tent") == 0;
}

static bool oxcical_export_recipient_table(ical_component &pevent_component,
    const char *org_name, cvt_id2user id2user, EXT_BUFFER_ALLOC alloc,
    const char *partstat, const MESSAGE_CONTENT *pmsg) try
{
	char tmp_value[334];

	if (pmsg->children.prcpts == nullptr)
		return true;
	auto str = pmsg->proplist.get<const char>(PR_MESSAGE_CLASS);
	if (str == nullptr)
		str = pmsg->proplist.get<char>(PR_MESSAGE_CLASS_A);
	if (str == nullptr)
		str = "IPM.Note";
	/* ignore ATTENDEE when METHOD is "PUBLIC" */
	if (class_match_prefix(str, "IPM.Appointment") == 0)
		return true;
	if (is_meeting_response(str)) {
		str = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
		if (str == nullptr)
			return true;
		auto piline = &pevent_component.append_line("ATTENDEE");
		piline->append_param("PARTSTAT", partstat);
		snprintf(tmp_value, sizeof(tmp_value), "MAILTO:%s", str);
		piline->append_value(nullptr, tmp_value);
		return true;
	}
	auto flag = pmsg->proplist.get<const uint8_t>(PR_RESPONSE_REQUESTED);
	auto b_rsvp = flag != nullptr && *flag != 0;
	for (auto &rcpt : *pmsg->children.prcpts) {
		auto rcptflags = rcpt.get<const uint32_t>(PR_RECIPIENT_FLAGS);
		if (rcptflags == nullptr)
			continue;
		if (*rcptflags & (recipExceptionalDeleted | recipOrganizer))
			continue;
		auto rcpttype = rcpt.get<const uint32_t>(PR_RECIPIENT_TYPE);
		if (rcpttype != nullptr && *rcpttype == MAPI_ORIG)
			continue;
		auto piline = &pevent_component.append_line("ATTENDEE");
		const char *role =
			rcpttype == nullptr ? "REQ-PARTICIPANT" :
			*rcpttype == MAPI_CC ? "OPT-PARTICIPANT" :
			*rcpttype == MAPI_BCC ? "NON-PARTICIPANT" :
			"REQ-PARTICIPANT";
		piline->append_param("ROLE", role);
		if (partstat != nullptr)
			piline->append_param("PARTSTAT", partstat);
		if (b_rsvp)
			piline->append_param("RSVP", "TRUE");
		auto name = rcpt.get<const char>(PR_DISPLAY_NAME);
		if (name != nullptr)
			piline->append_param("CN", name);
		std::string username;
		if (oxcmail_get_smtp_address(rcpt, nullptr /* tags_self */, org_name,
		    id2user, username)) {
			snprintf(tmp_value, std::size(tmp_value), "MAILTO:%s", username.c_str());
			piline->append_value(nullptr, tmp_value);
		}
	}
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2094: ENOMEM");
	return false;
}

static bool oxcical_export_rrule(const ical_component *ptz_component,
    ical_component &pcomponent, APPOINTMENT_RECUR_PAT *apr) try
{
	ical_time itime;
	const char *str_tag;

	str_tag = nullptr;
	switch (apr->recur_pat.calendartype) {
	case CAL_DEFAULT:
		switch (apr->recur_pat.patterntype) {
		case rptHjMonth:
		case rptHjMonthNth:
			str_tag = "X-MICROSOFT-RRULE";
			break;
		default:
			str_tag = "RRULE";
			break;
		}
		break;
	case CAL_GREGORIAN:
	case CAL_GREGORIAN_US:
	case CAL_JAPAN:
	case CAL_TAIWAN:
	case CAL_KOREA:
	case CAL_THAI:
	case CAL_GREGORIAN_ME_FRENCH:
	case CAL_GREGORIAN_ARABIC:
	case CAL_GREGORIAN_XLIT_ENGLISH:
	case CAL_GREGORIAN_XLIT_FRENCH:
		str_tag = "RRULE";
		break;
	case CAL_HIJRI:
	case CAL_HEBREW:
	case CAL_LUNAR_JAPANESE:
	case CAL_CHINESE_LUNAR:
	case CAL_SAKA:
	case CAL_LUNAR_ETO_CHN:
	case CAL_LUNAR_ETO_KOR:
	case CAL_LUNAR_ETO_ROKUYOU:
	case CAL_LUNAR_KOREAN:
	case CAL_UMALQURA:
		str_tag = "X-MICROSOFT-RRULE";
		break;
	}
	if (str_tag == nullptr)
		return false;
	auto piline = &pcomponent.append_line(str_tag);
	switch (apr->recur_pat.patterntype) {
	case rptMinute:
		piline->append_value("FREQ", "DAILY");
		piline->append_value("INTERVAL", std::to_string(apr->recur_pat.period / 1440));
		break;
	case rptWeek: {
		piline->append_value("FREQ", "WEEKLY");
		piline->append_value("INTERVAL", std::to_string(apr->recur_pat.period));
		auto &pivalue = piline->append_value("BYDAY");
		for (unsigned int wd = 0; wd < 7; ++wd)
			if (apr->recur_pat.pts.weekrecur & (1 << wd))
				pivalue.append_subval(weekday_to_str(wd));
		break;
	}
	case rptMonth:
	case rptHjMonth: {
		auto monthly = apr->recur_pat.period % 12 != 0;
		piline->append_value("FREQ", monthly ? "MONTHLY" : "YEARLY");
		if (monthly) {
			piline->append_value("INTERVAL", std::to_string(apr->recur_pat.period));
			if (apr->recur_pat.pts.dayofmonth == 31)
				piline->append_value("BYMONTHDAY", "-1");
			else
				piline->append_value("BYMONTHDAY", std::to_string(apr->recur_pat.pts.dayofmonth));
		} else {
			piline->append_value("INTERVAL", std::to_string(apr->recur_pat.period / 12));
			if (apr->recur_pat.pts.dayofmonth == 31)
				piline->append_value("BYMONTHDAY", "-1");
			else
				piline->append_value("BYMONTHDAY", std::to_string(apr->recur_pat.pts.dayofmonth));
			ical_get_itime_from_yearday(1601, apr->recur_pat.firstdatetime / 1440 + 1, &itime);
			piline->append_value("BYMONTH", std::to_string(itime.month));
		}
		break;
	}
	case rptMonthNth:
	case rptHjMonthNth: {
		auto monthly = apr->recur_pat.period % 12 != 0;
		piline->append_value("FREQ", monthly ? "MONTHLY" : "YEARLY");
		if (monthly) {
			piline->append_value("INTERVAL", std::to_string(apr->recur_pat.period));
			auto &pivalue = piline->append_value("BYDAY");
			for (unsigned int wd = 0; wd < 7; ++wd)
				if (apr->recur_pat.pts.monthnth.weekrecur & (1 << wd))
					pivalue.append_subval(weekday_to_str(wd));
			if (apr->recur_pat.pts.monthnth.recurnum == 5)
				piline->append_value("BYSETPOS", "-1");
			else
				piline->append_value("BYSETPOS", std::to_string(apr->recur_pat.pts.monthnth.recurnum));
		} else {
			piline->append_value("INTERVAL", std::to_string(apr->recur_pat.period / 12));
			auto &pivalue = piline->append_value("BYDAY");
			for (unsigned int wd = 0; wd < 7; ++wd)
				if (apr->recur_pat.pts.monthnth.weekrecur & (1 << wd))
					pivalue.append_subval(weekday_to_str(wd));
			if (apr->recur_pat.pts.monthnth.recurnum == 5)
				piline->append_value("BYSETPOS", "-1");
			else
				piline->append_value("BYSETPOS", std::to_string(apr->recur_pat.pts.monthnth.recurnum));
			piline->append_value("BYMONTH", std::to_string(apr->recur_pat.firstdatetime));
		}
		break;
	}
	default:
		return false;
	}
	if (apr->recur_pat.endtype == IDC_RCEV_PAT_ERB_AFTERNOCCUR) {
		piline->append_value("COUNT", std::to_string(apr->recur_pat.occurrencecount));
	} else if (apr->recur_pat.endtype == IDC_RCEV_PAT_ERB_END) {
		auto unix_time = rop_util_rtime_to_unix(apr->recur_pat.enddate + apr->starttimeoffset);
		ical_utc_to_datetime(nullptr, unix_time, &itime);
		if (!ical_itime_to_utc(ptz_component, itime, &unix_time))
			return false;
		ical_utc_to_datetime(nullptr, unix_time, &itime);
		char tmp_buff[1024];
		sprintf_dtutc(tmp_buff, std::size(tmp_buff), itime);
		piline->append_value("UNTIL", tmp_buff);
	}
	if (apr->recur_pat.patterntype == rptWeek) {
		auto wd = weekday_to_str(apr->recur_pat.firstdow);
		if (wd == nullptr)
			return false;
		piline->append_value("WKST", wd);
	}
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2091: ENOMEM");
	return false;
}

static bool oxcical_check_exdate(APPOINTMENT_RECUR_PAT *apr)
{
	bool b_found;
	size_t count = 0;
	for (size_t i = 0; i < apr->recur_pat.deletedinstancecount; ++i) {
		b_found = false;
		for (size_t j = 0; j < apr->exceptioncount; ++j) {
			if (apr->recur_pat.pdeletedinstancedates[i]
				== apr->pexceptioninfo[j].originalstartdate &&
				0 != apr->pexceptioninfo[j].overrideflags) {
				b_found = true;
				break;
			}
		}
		if (!b_found)
			count ++;
	}
	return count != 0;
}

static bool oxcical_export_exdate(const char *tzid, bool b_date,
    ical_component &pcomponent, APPOINTMENT_RECUR_PAT *apr) try
{
	bool b_found;
	ical_time itime;
	char tmp_buff[1024];
	ical_line *piline;

	if (apr->recur_pat.calendartype != CAL_DEFAULT ||
	    apr->recur_pat.patterntype == rptHjMonth ||
	    apr->recur_pat.patterntype == rptHjMonthNth)
		piline = &pcomponent.append_line("X-MICROSOFT-EXDATE");
	else
		piline = &pcomponent.append_line("EXDATE");
	auto &pivalue = piline->append_value();
	if (b_date)
		piline->append_param("VALUE", "DATE");
	if (tzid != nullptr)
		piline->append_param("TZID", tzid);
	for (size_t i = 0; i < apr->recur_pat.deletedinstancecount; ++i) {
		b_found = false;
		for (size_t j = 0; j < apr->exceptioncount; ++j) {
			if (apr->recur_pat.pdeletedinstancedates[i]
				== apr->pexceptioninfo[j].originalstartdate &&
				0 != apr->pexceptioninfo[j].overrideflags) {
				b_found = true;
				break;
			}
		}
		if (b_found)
			continue;
		ical_utc_to_datetime(nullptr, rop_util_rtime_to_unix(apr->recur_pat.pdeletedinstancedates[i] + apr->starttimeoffset), &itime);
		if (b_date)
			sprintf_dt(tmp_buff, std::size(tmp_buff), itime);
		else if (tzid == nullptr)
			sprintf_dtutc(tmp_buff, std::size(tmp_buff), itime);
		else
			sprintf_dtlcl(tmp_buff, std::size(tmp_buff), itime);
		pivalue.append_subval(tmp_buff);
	}
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2095: ENOMEM");
	return false;
}

static bool oxcical_check_rdate(APPOINTMENT_RECUR_PAT *apr)
{
	size_t count = 0;
	bool b_found;

	for (size_t i = 0; i < apr->recur_pat.modifiedinstancecount; ++i) {
		b_found = false;
		for (size_t j = 0; j < apr->exceptioncount; ++j) {
			if (apr->recur_pat.pmodifiedinstancedates[i]
				== apr->pexceptioninfo[j].startdatetime &&
				0 != apr->pexceptioninfo[j].overrideflags) {
				b_found = true;
				break;
			}
		}
		if (!b_found)
			count ++;
	}
	return count != 0;
}

static bool oxcical_export_rdate(const char *tzid, bool b_date,
     ical_component &pcomponent, APPOINTMENT_RECUR_PAT *apr) try
{
	bool b_found;
	ical_time itime;
	char tmp_buff[1024];

	auto piline = &pcomponent.append_line("RDATE");
	auto &pivalue = piline->append_value();
	if (b_date)
		piline->append_param("VALUE", "DATE");
	if (tzid != nullptr)
		piline->append_param("TZID", tzid);
	for (size_t i = 0; i < apr->recur_pat.modifiedinstancecount; ++i) {
		b_found = false;
		for (size_t j = 0; j < apr->exceptioncount; ++j) {
			if (apr->recur_pat.pmodifiedinstancedates[i]
				== apr->pexceptioninfo[j].startdatetime &&
				0 != apr->pexceptioninfo[j].overrideflags) {
				b_found = true;
				break;
			}
		}
		if (b_found)
			continue;
		ical_utc_to_datetime(nullptr, rop_util_rtime_to_unix(apr->recur_pat.pmodifiedinstancedates[i]), &itime);
		if (b_date)
			sprintf_dt(tmp_buff, std::size(tmp_buff), itime);
		else if (tzid == nullptr)
			sprintf_dtutc(tmp_buff, std::size(tmp_buff), itime);
		else
			sprintf_dtlcl(tmp_buff, std::size(tmp_buff), itime);
		pivalue.append_subval(tmp_buff);
	}
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2096: ENOMEM");
	return false;
}

static void oxcical_export_organizer(const MESSAGE_CONTENT &msg,
    ical_component &com, const char *org_name, cvt_id2user id2user)
{
	char buf[UADDR_SIZE];
	auto str = msg.proplist.get<char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (str != nullptr) {
		str = msg.proplist.get<char>(PR_SENT_REPRESENTING_ADDRTYPE);
		if (str == nullptr)
			return;
		if (strcasecmp(str, "SMTP") == 0) {
			str = msg.proplist.get<char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
		} else if (strcasecmp(str, "EX") == 0) {
			str = msg.proplist.get<char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
			if (str != nullptr) {
				auto ret = cvt_essdn_to_username(str, org_name,
				           std::move(id2user), buf, std::size(buf));
				str = ret == ecSuccess ? buf : nullptr;
			}
		}
	}
	if (str == nullptr)
		return;
	char buf1[UADDR_SIZE+10];
	snprintf(buf1, std::size(buf1), "MAILTO:%s", str);
	auto line = &com.append_line("ORGANIZER", buf1);
	str = msg.proplist.get<char>(PR_SENT_REPRESENTING_NAME);
	if (str != nullptr)
		line->append_param("CN", str);
}

#define E_2201 "E-2201: get_propids failed for an unspecified reason"

static const char *oxcical_export_uid(const MESSAGE_CONTENT &msg,
    ical_component &com, EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids)
{
	const PROPERTY_NAME propname = {MNID_ID, PSETID_Meeting, PidLidGlobalObjectId};
	const PROPNAME_ARRAY propnames = {1, deconst(&propname)};
	PROPID_ARRAY propids;
	char buf[1024], buf1[2048];
	GLOBALOBJECTID goid;

	if (!get_propids(&propnames, &propids) || propids.size() != 1)
		return E_2201;
	auto bin = msg.proplist.get<BINARY>(PROP_TAG(PT_BINARY, propids[0]));
	if (bin != nullptr) {
		EXT_PULL ext_pull;

		ext_pull.init(bin->pb, bin->cb, alloc, 0);
		if (ext_pull.g_goid(&goid) != EXT_ERR_SUCCESS)
			return "E-2215: PidLidGlobalObjectId contents not recognized";
		if (goid.data.pb != nullptr && goid.data.cb >= 12 &&
		    memcmp(goid.data.pb, ThirdPartyGlobalId, 12) == 0) {
			if (goid.data.cb - 12 > sizeof(buf) - 1) {
				memcpy(buf, &goid.data.pb[12], std::size(buf) - 1);
				buf[std::size(buf)-1] = '\0';
			} else {
				memcpy(buf, &goid.data.pb[12], goid.data.cb - 12);
				buf[goid.data.cb-12] = '\0';
			}
			com.append_line("UID", buf);
		} else {
			EXT_PUSH ext_push;

			goid.year = 0;
			goid.month = 0;
			goid.day = 0;
			if (!ext_push.init(buf, sizeof(buf), 0) ||
			    ext_push.p_goid(goid) != EXT_ERR_SUCCESS)
				return "E-2223";
			if (!encode_hex_binary(buf, ext_push.m_offset,
			    buf1, sizeof(buf1)))
				return "E-2216";
			HX_strupper(buf1);
			com.append_line("UID", buf1);
		}
	} else {
		goid.arrayid = EncodedGlobalId;
		goid.creationtime = rop_util_unix_to_nttime(time(nullptr));
		goid.data.cb = 16;
		goid.data.pc = buf1;
		EXT_PUSH ext_push;
		if (!ext_push.init(buf1, 16, 0) ||
		    ext_push.p_guid(GUID::random_new()) != EXT_ERR_SUCCESS ||
		    !ext_push.init(buf, std::size(buf), 0) ||
		    ext_push.p_goid(goid) != EXT_ERR_SUCCESS)
			return "E-2224";
		if (!encode_hex_binary(buf, ext_push.m_offset, buf1,
		    sizeof(buf1)))
			return "E-2217";
		HX_strupper(buf1);
		com.append_line("UID", buf1);
	}
	return nullptr;
}

static void append_dt(ical_component &com, const char *key,
    const ical_time &itime, bool b_date, const char *tzid)
{
	char txt[64];
	if (b_date)
		sprintf_dt(txt, std::size(txt), itime);
	else if (tzid == nullptr)
		sprintf_dtutc(txt, std::size(txt), itime);
	else
		sprintf_dtlcl(txt, std::size(txt), itime);
	auto line = &com.append_line(key, txt);
	if (b_date)
		line->append_param("VALUE", "DATE");
	if (tzid != nullptr)
		line->append_param("TZID", tzid);
}

static const char *oxcical_export_recid(const MESSAGE_CONTENT &msg,
    uint32_t proptag_xrt, bool b_exceptional, bool b_date,
    ical_component &com, const ical_component *ptz_component,
    const char *tzid, EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids)
{
	ical_time itime{};
	bool itime_is_set = false;

	auto lnum = msg.proplist.get<uint64_t>(proptag_xrt);
	if (lnum == nullptr) {
		const PROPERTY_NAME namequeries[] = {
			{MNID_ID, PSETID_Meeting, PidLidIsException},
			{MNID_ID, PSETID_Meeting, PidLidStartRecurrenceTime},
			{MNID_ID, PSETID_Meeting, PidLidGlobalObjectId},
		};
		enum {
			l_is_except = 0, l_startrecurtime, l_goid,
		};
		static_assert(l_goid + 1 == std::size(namequeries));
		const PROPNAME_ARRAY propnames = {std::size(namequeries), deconst(namequeries)};
		PROPID_ARRAY propids;

		if (!get_propids(&propnames, &propids) || propids.size() != propnames.size())
			return E_2201;
		auto flag = msg.proplist.get<const uint8_t>(PROP_TAG(PT_BOOLEAN, propids[l_is_except]));
		if (flag != nullptr && *flag != 0) {
			auto num = msg.proplist.get<const uint32_t>(PROP_TAG(PT_LONG, propids[l_startrecurtime]));
			if (num != nullptr) {
				itime.hour   = (*num >> 12) & 0x1f;
				itime.minute = (*num >> 6) & 0x3f;
				itime.second = *num & 0x3f;
				itime_is_set = true;
				auto bin = msg.proplist.get<BINARY>(PROP_TAG(PT_BINARY, propids[l_goid]));
				if (bin != nullptr) {
					EXT_PULL ext_pull;
					GLOBALOBJECTID globalobjectid;

					ext_pull.init(bin->pb, bin->cb, alloc, 0);
					if (ext_pull.g_goid(&globalobjectid) != EXT_ERR_SUCCESS)
						return "E-2218: PidLidGlobalObjectId contents not recognized";
					itime.year = globalobjectid.year;
					itime.month = globalobjectid.month;
					itime.day = globalobjectid.day;
				}
			}
		}
	} else {
		if (!ical_utc_to_datetime(ptz_component,
		    rop_util_nttime_to_unix(*lnum), &itime))
			return "E-2219";
		itime_is_set = true;
	}
	if (!itime_is_set) {
		if (b_exceptional)
			return "E-2220";
	} else {
		append_dt(com, "RECURRENCE-ID", itime, b_date,
			ptz_component != nullptr ? tzid : nullptr);
	}
	return nullptr;
}

static const char *oxcical_export_task(const MESSAGE_CONTENT &msg,
    ical_component &com, const ical_component *tzcom,
    const char *tzid, GET_PROPIDS get_propids)
{
	const PROPERTY_NAME namequeries[] = {
		{MNID_ID, PSETID_Task, PidLidTaskStatus},
		{MNID_ID, PSETID_Task, PidLidPercentComplete},
		{MNID_ID, PSETID_Task, PidLidTaskDueDate},
		{MNID_ID, PSETID_Task, PidLidTaskDateCompleted},
	};
	enum {
		l_taskstatus = 0, l_pctcomplete, l_duedate, l_datecompl,
	};
	static_assert(l_datecompl + 1 == std::size(namequeries));
	const PROPNAME_ARRAY propnames = {std::size(namequeries), deconst(namequeries)};
	PROPID_ARRAY propids;

	if (!get_propids(&propnames, &propids) || propids.size() != propnames.size())
		return E_2201;
	auto num = msg.proplist.get<uint32_t>(PROP_TAG(PT_LONG, propids[l_taskstatus]));
	if (num != nullptr)
		com.append_line("STATUS",
			*num == tsvNotStarted ? "NEEDS-ACTION" :
			*num == tsvComplete ? "COMPLETED" : "IN-PROGRESS");

	auto dbl = msg.proplist.get<const double>(PROP_TAG(PT_DOUBLE, propids[l_pctcomplete]));
	if (dbl != nullptr) {
		auto v = std::clamp(static_cast<unsigned int>(100 * *dbl), 0U, 100U);
		com.append_line("PERCENT-COMPLETE", std::to_string(v));
	}

	auto lnum = msg.proplist.get<const uint64_t>(PROP_TAG(PT_SYSTIME, propids[l_duedate]));
	if (lnum != nullptr) {
		ical_time itime;
		if (!ical_utc_to_datetime(tzcom, rop_util_nttime_to_unix(*lnum), &itime))
			return "E-2221";
		append_dt(com, "DUE", itime, false, tzid);
	}

	lnum = msg.proplist.get<const uint64_t>(PROP_TAG(PT_SYSTIME, propids[l_datecompl]));
	if (lnum != nullptr) {
		ical_time itime;
		if (!ical_utc_to_datetime(tzcom, rop_util_nttime_to_unix(*lnum), &itime))
			return "E-2001";
		append_dt(com, "COMPLETED", itime, false, tzid);
	}
	return nullptr;
}

static void busystatus_to_line(ol_busy_status status, const char *key,
    ical_component *com)
{
	auto it = std::lower_bound(std::cbegin(busy_status_names),
	          std::cend(busy_status_names), status,
	          [](const auto &p, ol_busy_status v) { return p.first < v; });
	if (it != std::cend(busy_status_names) && it->first == status)
		com->append_line(key, it->second);
}

static void sensitivity_to_line(mapi_sensitivity n, ical_component *c)
{
	c->append_line("CLASS",
		n == SENSITIVITY_PERSONAL ? "PERSONAL" :
		n == SENSITIVITY_PRIVATE ? "PRIVATE" :
		n == SENSITIVITY_COMPANY_CONFIDENTIAL ? "CONFIDENTIAL" :
		"PUBLIC");
}

static void importance_to_lines(mapi_importance n, ical_component *c)
{
	/* RFC 5545 §3.8.1.9 / MS-OXCICAL v13 §2.1.3.1.1.20.17 pg 58 */
	if (n == IMPORTANCE_LOW) {
		c->append_line("PRIORITY", "9");
		c->append_line("X-MICROSOFT-CDO-IMPORTANCE", "0");
	} else if (n == IMPORTANCE_NORMAL) {
		c->append_line("PRIORITY", "5");
		c->append_line("X-MICROSOFT-CDO-IMPORTANCE", "1");
	} else if (n == IMPORTANCE_HIGH) {
		c->append_line("PRIORITY", "1");
		c->append_line("X-MICROSOFT-CDO-IMPORTANCE", "2");
	} else {
		c->append_line("PRIORITY", "9");
	}
}

static std::string oxcical_export_valarm(const MESSAGE_CONTENT &msg,
    ical_component &pical, GET_PROPIDS get_propids)
{
	const PROPERTY_NAME namequeries[] = {
		{MNID_ID, PSETID_Common, PidLidReminderSet},
		{MNID_ID, PSETID_Common, PidLidReminderDelta},
	};
	enum { l_remset = 0, l_remdelta };
	static_assert(l_remdelta + 1 == std::size(namequeries));
	const PROPNAME_ARRAY propnames = {std::size(namequeries), deconst(namequeries)};
	PROPID_ARRAY propids;

	if (!get_propids(&propnames, &propids) || propids.size() != propnames.size())
		return E_2201;
	auto flag = msg.proplist.get<uint8_t>(PROP_TAG(PT_BOOLEAN, propids[l_remset]));
	if (flag == nullptr || *flag == 0)
		return {};
	auto com = &pical.append_comp("VALARM");
	com->append_line("DESCRIPTION", "REMINDER");
	auto num = msg.proplist.get<uint32_t>(PROP_TAG(PT_LONG, propids[l_remdelta]));
	char tmp_buff[32];
	if (num == nullptr || *num == ENDDATE_MISSING_RDELTA)
		strcpy(tmp_buff, "-PT15M");
	else
		snprintf(tmp_buff, std::size(tmp_buff), "-PT%uM", *num);
	auto line = &com->append_line("TRIGGER", tmp_buff);
	line->append_param("RELATED", "START");
	com->append_line("ACTION", "DISPLAY");
	return {};
}

static std::string oxcical_export_internal(const char *method, const char *tzid,
    const MESSAGE_CONTENT *pmsg, const char *log_id, ical &pical,
    const char *org_name, cvt_id2user id2user, EXT_BUFFER_ALLOC alloc,
    GET_PROPIDS get_propids) try
{
	const PROPERTY_NAME namequeries[] = {
		{MNID_ID, PSETID_Appointment, PidLidAppointmentCounterProposal},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentProposedStartWhole},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentProposedEndWhole},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentStartWhole},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentEndWhole},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentDuration},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentRecur},
		{MNID_ID, PSETID_Appointment, PidLidTimeZoneStruct},
		{MNID_ID, PSETID_Appointment, PidLidTimeZoneDescription},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentTimeZoneDefinitionRecur},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentTimeZoneDefinitionStartDisplay},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentTimeZoneDefinitionEndDisplay},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentSubType},
		{MNID_ID, PSETID_Appointment, PidLidExceptionReplaceTime},
		{MNID_ID, PSETID_Task, PidLidTaskStartDate},
		{MNID_STRING, PS_PUBLIC_STRINGS, 0, deconst(PidNameKeywords)},
		{MNID_ID, PSETID_Meeting, PidLidAttendeeCriticalChange},
		{MNID_ID, PSETID_Meeting, PidLidOwnerCriticalChange},
		{MNID_ID, PSETID_Appointment, PidLidBusyStatus},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentSequence},
		{MNID_ID, PSETID_Appointment, PidLidLocation},
		{MNID_STRING, PS_PUBLIC_STRINGS, 0, deconst(PidNameLocationUrl)},
		{MNID_ID, PSETID_Appointment, PidLidIntendedBusyStatus},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentNotAllowPropose},
	};
	enum {
		l_counterproposal, l_proposedstartwhole, l_proposedendwhole,
		l_startwhole, l_endwhole, l_duration, l_recur, l_tzstruct,
		l_tzdesc, l_tzdefrecur, l_tzdefstart, l_tzdefend, l_subtype, l_replacetime,
		l_taskstart, l_keywords, l_attcritchg, l_ownercritchg, l_busystatus,
		l_apptseq, l_location, l_locationurl, l_intendedbusy, l_nopropose,
	};
	static_assert(l_nopropose + 1 == std::size(namequeries));
	PROPID_ARRAY propids;
	APPOINTMENT_RECUR_PAT apprecurr;

	const PROPNAME_ARRAY pna = {std::size(namequeries), deconst(namequeries)};
	if (!get_propids(&pna, &propids) || propids.size() != pna.size())
		return E_2201;

	auto num = pmsg->proplist.get<const uint32_t>(PR_MESSAGE_LOCALE_ID);
	auto planguage = num != nullptr ? lcid_to_ltag(*num) : nullptr;
	auto str = pmsg->proplist.get<const char>(PR_MESSAGE_CLASS);
	if (str == nullptr)
		str = pmsg->proplist.get<char>(PR_MESSAGE_CLASS_A);
	if (str == nullptr)
		str = "IPM.Note";
	auto icaltype = "VEVENT";
	const char *partstat = nullptr;
	bool b_proposal = false, b_exceptional = true, b_recurrence = false;
	if (method == nullptr) {
		b_exceptional = false;
		if (class_match_prefix(str, "IPM.Appointment") == 0) {
			method = "PUBLISH";
		} else if (class_match_prefix(str, "IPM.Schedule.Meeting.Request") == 0) {
			method = "REQUEST";
			partstat = "NEEDS-ACTION";
		} else if (class_match_prefix(str, "IPM.Schedule.Meeting.Resp.Pos") == 0) {
			method = "REPLY";
			partstat = "ACCEPTED";
		} else if (class_match_prefix(str, "IPM.Schedule.Meeting.Resp.Tent") == 0) {
			partstat = "TENTATIVE";
			auto flag = pmsg->proplist.get<const uint8_t>(PROP_TAG(PT_BOOLEAN, propids[l_counterproposal]));
			if (flag != nullptr && *flag != 0) {
				b_proposal = true;
				method = "COUNTER";
			} else {
				method = "REPLY";
			}
		} else if (class_match_prefix(str, "IPM.Schedule.Meeting.Resp.Neg") == 0) {
			method = "REPLY";
			partstat = "DECLINED";
		} else if (class_match_prefix(str, "IPM.Schedule.Meeting.Canceled") == 0) {
			method = "CANCEL";
			partstat = "NEEDS-ACTION";
		} else if (class_match_prefix(str, "IPM.Task") == 0) {
			method = "";
			icaltype = nullptr;
			pical.m_name = "VTODO";
		} else if (class_match_prefix(str, "IPM.Activity") == 0) {
			method = "";
			icaltype = nullptr;
			pical.m_name = "VJOURNAL";
		} else {
			return fmt::format("W-2060: oxcical_export does not handle message class \"{}\"", str);
		}
	}
	auto lnum = pmsg->proplist.get<const uint64_t>(PROP_TAG(PT_SYSTIME,
	            propids[b_proposal ? l_proposedstartwhole : l_startwhole]));
	bool has_start_time = false;
	time_t start_time = 0, end_time = 0;
	if (lnum != nullptr) {
		start_time = rop_util_nttime_to_unix(*lnum);
		has_start_time = true;
		lnum = pmsg->proplist.get<uint64_t>(PROP_TAG(PT_SYSTIME, propids[b_proposal ? l_proposedendwhole : l_endwhole]));
		if (lnum != nullptr) {
			end_time = rop_util_nttime_to_unix(*lnum);
		} else {
			end_time = start_time;
			num = pmsg->proplist.get<uint32_t>(PROP_TAG(PT_LONG, propids[l_duration]));
			if (num != nullptr)
				end_time += *num;
		}
	}

	ical_component *ptz_component = nullptr;
	if (!b_exceptional) {

		if (*method != '\0')
			pical.append_line("METHOD", method);
		pical.append_line("PRODID", "gromox-oxcical");
		pical.append_line("VERSION", "2.0");

		auto bin = pmsg->proplist.get<const BINARY>(PROP_TAG(PT_BINARY, propids[l_recur]));
		if (bin != nullptr) {
			EXT_PULL ext_pull;
			ext_pull.init(bin->pb, bin->cb, alloc, EXT_FLAG_UTF16);
			if (ext_pull.g_apptrecpat(&apprecurr) != EXT_ERR_SUCCESS)
				return "E-2204: PidLidAppointmentRecur contents not recognized";
			b_recurrence = true;
		}

		if (b_recurrence) {
			auto it = std::lower_bound(cal_scale_names, std::end(cal_scale_names),
				  apprecurr.recur_pat.calendartype,
				  [&](const auto &p, unsigned int v) { return p.first < v; });
			str = it != std::end(cal_scale_names) &&
			      it->first == apprecurr.recur_pat.calendartype ?
			      it->second : nullptr;
			if (apprecurr.recur_pat.patterntype == rptHjMonth ||
			    apprecurr.recur_pat.patterntype == rptHjMonthNth)
				str = "Hijri";
			if (str != nullptr)
				pical.append_line("X-MICROSOFT-CALSCALE", str);
		}

		struct tm tmp_tm;
		unsigned int year = 1601;
		if (has_start_time && gmtime_r(&start_time, &tmp_tm) != nullptr)
			year = tmp_tm.tm_year + 1900;

		tzid = NULL;
		if (b_recurrence) {
			bin = pmsg->proplist.get<BINARY>(PROP_TAG(PT_BINARY, propids[l_tzdefrecur]));
			if (bin != nullptr) {
				EXT_PULL ext_pull;
				TIMEZONEDEFINITION tz_definition;
				TIMEZONESTRUCT tz_struct;

				ext_pull.init(bin->pb, bin->cb, alloc, 0);
				if (ext_pull.g_tzdef(&tz_definition) != EXT_ERR_SUCCESS)
					return "E-2207: PidLidAppointmentTimeZoneDefinitionRecur contents not recognized";
				tzid = tz_definition.keyname;
				oxcical_convert_to_tzstruct(&tz_definition, &tz_struct);
				ptz_component = oxcical_export_timezone(
						pical, year - 1, tzid, &tz_struct);
				if (ptz_component == nullptr)
					return "E-2208: export_timezone returned an unspecified error";
			}
		} else {
			bin = pmsg->proplist.get<BINARY>(PROP_TAG(PT_BINARY, propids[l_tzdefstart]));
			if (bin != nullptr)
				bin = pmsg->proplist.get<BINARY>(PROP_TAG(PT_BINARY, propids[l_tzdefend]));
			if (bin != nullptr) {
				EXT_PULL ext_pull;
				TIMEZONEDEFINITION tz_definition;
				TIMEZONESTRUCT tz_struct;

				ext_pull.init(bin->pb, bin->cb, alloc, 0);
				if (ext_pull.g_tzdef(&tz_definition) != EXT_ERR_SUCCESS)
					return "E-2209: PidLidAppointmentTimeZoneDefinitionEndDisplay contents not recognized";
				tzid = tz_definition.keyname;
				oxcical_convert_to_tzstruct(&tz_definition, &tz_struct);
				ptz_component = oxcical_export_timezone(
						pical, year - 1, tzid, &tz_struct);
				if (ptz_component == nullptr)
					return "E-2210: export_timezone returned an unspecified error";
			}
		}
		if (ptz_component == nullptr) {
			bin = pmsg->proplist.get<BINARY>(PROP_TAG(PT_BINARY, propids[l_tzstruct]));
			tzid = pmsg->proplist.get<char>(PROP_TAG(PT_UNICODE, propids[l_tzdesc]));
			if (tzid != nullptr && *tzid == '\0')
				tzid = nullptr;
			if (bin != nullptr && bin->cb > 0 && tzid != nullptr) {
				EXT_PULL ext_pull;
				TIMEZONESTRUCT tz_struct;

				ext_pull.init(bin->pb, bin->cb, alloc, 0);
				if (ext_pull.g_tzstruct(&tz_struct) != EXT_ERR_SUCCESS) {
					mlog(LV_ERR, "E-2205: %s: PidLidTimeZoneStruct contents not recognized so TZ won't be exported", log_id);
				} else {
					ptz_component = oxcical_export_timezone(
							pical, year - 1, tzid, &tz_struct);
					if (ptz_component == nullptr)
						mlog(LV_ERR, "E-2206: %s: export_timezone returned an unspecified error and won't be exported", log_id);
				}
			}
		}
	}

	auto snum = pmsg->proplist.get<const uint8_t>(PROP_TAG(PT_BOOLEAN, propids[l_subtype]));
	bool b_allday = snum != nullptr && *snum != 0;
	auto pcomponent = icaltype != nullptr ? &pical.append_comp(icaltype) : &pical;

	if (strcmp(method, "REQUEST") == 0 || strcmp(method, "CANCEL") == 0)
		oxcical_export_organizer(*pmsg, *pcomponent, org_name, id2user);
	if (!oxcical_export_recipient_table(*pcomponent, org_name,
	    id2user, alloc, partstat, pmsg))
		return "E-2211: export_recipient_table - unspecified error";

	str = pmsg->proplist.get<char>(PR_BODY);
	if (str != nullptr) {
		auto kw = strcmp(method, "REPLY") == 0 ||
		          strcmp(method, "COUNTER") == 0 ?
		          "COMMENT" : "DESCRIPTION";
		auto piline = &pcomponent->append_line(kw, str);
		if (planguage != nullptr)
			piline->append_param("LANGUAGE", planguage);
	}
	/* IPM.Activity is RTF-only in Outlook, nothing in PR_BODY */

	if (!b_exceptional && b_recurrence) {
		if (!oxcical_export_rrule(ptz_component, *pcomponent, &apprecurr))
			return "E-2212: export_rrule - unspecified error";
		if (oxcical_check_exdate(&apprecurr) &&
		    !oxcical_export_exdate(tzid, b_allday && g_oxcical_allday_ymd,
		    *pcomponent, &apprecurr))
			return "E-2213: export_exdate - unspecified error";
		if (oxcical_check_rdate(&apprecurr) &&
		    !oxcical_export_rdate(tzid, b_allday && g_oxcical_allday_ymd,
		    *pcomponent, &apprecurr))
			return "E-2214: export_rdate - unspecified error";
	}

	auto err = oxcical_export_uid(*pmsg, *pcomponent, alloc, get_propids);
	if (err != nullptr)
		return err;

	auto proptag_xrt = PROP_TAG(PT_SYSTIME, propids[l_replacetime]);
	err = oxcical_export_recid(*pmsg, proptag_xrt, b_exceptional,
	      b_allday && g_oxcical_allday_ymd, *pcomponent, ptz_component,
	      tzid, alloc, get_propids);
	if (err != nullptr)
		return err;

	str = pmsg->proplist.get<char>(PR_SUBJECT);
	if (str != nullptr) {
		auto piline = &pcomponent->append_line("SUMMARY", str);
		if (planguage != nullptr)
			piline->append_param("LANGUAGE", planguage);
	}

	if (has_start_time) {
		ical_time itime;
		if (!ical_utc_to_datetime(ptz_component, start_time, &itime))
			return "E-2002";
		append_dt(*pcomponent, "DTSTART", itime,
			b_allday && g_oxcical_allday_ymd,
			ptz_component != nullptr ? tzid : nullptr);
	} else {
		lnum = pmsg->proplist.get<const uint64_t>(PROP_TAG(PT_SYSTIME, propids[l_taskstart]));
		if (lnum != nullptr) {
			ical_time itime;
			if (!ical_utc_to_datetime(ptz_component, rop_util_nttime_to_unix(*lnum), &itime))
				return "E-2003";
			append_dt(*pcomponent, "DTSTART", itime,
				b_allday && g_oxcical_allday_ymd,
				ptz_component != nullptr ? tzid : nullptr);
		}
	}

	if (has_start_time && start_time != end_time) {
		ical_time itime;
		if (!ical_utc_to_datetime(ptz_component, end_time, &itime))
			return "E-2222";
		append_dt(*pcomponent, "DTEND", itime,
			b_allday && g_oxcical_allday_ymd,
			ptz_component != nullptr ? tzid : nullptr);
	}

	err = oxcical_export_task(*pmsg, *pcomponent, ptz_component,
	      tzid, get_propids);
	if (err != nullptr)
		return err;

	auto sa = pmsg->proplist.get<const STRING_ARRAY>(PROP_TAG(PT_MV_UNICODE, propids[l_keywords]));
	if (sa != nullptr) {
		auto piline = &pical.append_line("CATEGORIES");
		auto &pivalue = piline->append_value();
		for (size_t i = 0; i < sa->count; ++i)
			pivalue.append_subval(sa->ppstr[i]);
	}

	num = pmsg->proplist.get<uint32_t>(PR_SENSITIVITY);
	sensitivity_to_line(num != nullptr ? static_cast<mapi_sensitivity>(*num) :
		SENSITIVITY_NONE, pcomponent);
	num = pmsg->proplist.get<uint32_t>(PR_IMPORTANCE);
	if (num != nullptr)
		importance_to_lines(static_cast<mapi_importance>(*num), pcomponent);
	auto ll_crittype = strcmp(method, "REPLY") == 0 || strcmp(method, "COUNTER") == 0 ?
	                   l_attcritchg : l_ownercritchg;
	lnum = pmsg->proplist.get<uint64_t>(PROP_TAG(PT_SYSTIME, propids[ll_crittype]));
	if (lnum != nullptr) {
		ical_time itime;
		char tmp_buff[1024];
		ical_utc_to_datetime(nullptr, rop_util_nttime_to_unix(*lnum), &itime);
		sprintf_dtutc(tmp_buff, std::size(tmp_buff), itime);
		pcomponent->append_line("DTSTAMP", tmp_buff);
	}

	auto pbusystatus = pmsg->proplist.get<uint32_t>(PROP_TAG(PT_LONG, propids[l_busystatus]));
	if (pbusystatus != nullptr) {
		switch (static_cast<ol_busy_status>(*pbusystatus)) {
		case olFree:
		case olWorkingElsewhere:
			pcomponent->append_line("TRANSP", "TRANSPARENT");
			break;
		case olTentative:
		case olBusy:
		case olOutOfOffice:
			pcomponent->append_line("TRANSP", "OPAQUE");
			break;
		default:
			break;
		}
	}

	auto psequence = pmsg->proplist.get<uint32_t>(PROP_TAG(PT_LONG, propids[l_apptseq]));
	if (psequence != nullptr)
		pcomponent->append_line("SEQUENCE", std::to_string(*psequence));

	str = pmsg->proplist.get<char>(PROP_TAG(PT_UNICODE, propids[l_location]));
	if (str != nullptr) {
		auto piline = &pcomponent->append_line("LOCATION", str);
		str = pmsg->proplist.get<char>(PROP_TAG(PT_UNICODE, propids[l_locationurl]));
		if (str != nullptr)
			piline->append_param("ALTREP", str);
		if (planguage != nullptr)
			piline->append_param("LANGUAGE", planguage);
	}

	if (psequence != nullptr)
		pcomponent->append_line("X-MICROSOFT-CDO-APPT-SEQUENCE", std::to_string(*psequence));
	auto inum = pmsg->proplist.get<int32_t>(PR_OWNER_APPT_ID);
	if (inum != nullptr)
		pcomponent->append_line("X-MICROSOFT-CDO-OWNERAPPTID", std::to_string(*inum));
	if (pbusystatus != nullptr)
		busystatus_to_line(static_cast<ol_busy_status>(*pbusystatus),
			"X-MICROSOFT-CDO-BUSYSTATUS", pcomponent);

	num = pmsg->proplist.get<uint32_t>(PROP_TAG(PT_LONG, propids[l_intendedbusy]));
	if (num != nullptr)
		busystatus_to_line(static_cast<ol_busy_status>(*num),
			"X-MICROSOFT-CDO-INTENDEDSTATUS", pcomponent);

	pcomponent->append_line("X-MICROSOFT-CDO-ALLDAYEVENT", b_allday ? "TRUE" : "FALSE");
	pcomponent->append_line("X-MICROSOFT-CDO-INSTTYPE", b_exceptional ? "3" : b_recurrence ? "1" : "0");

	auto flag = pmsg->proplist.get<uint8_t>(PROP_TAG(PT_BOOLEAN, propids[l_nopropose]));
	if (flag != nullptr)
		pcomponent->append_line("X-MICROSOFT-DISALLOW-COUNTER", *flag != 0 ? "TRUE" : "FALSE");

	if (!b_exceptional && pmsg->children.pattachments != nullptr) {
		for (auto &attachment : *pmsg->children.pattachments) {
			auto pembedded = attachment.pembedded;
			if (pembedded == nullptr)
				continue;
			str = pembedded->proplist.get<char>(PR_MESSAGE_CLASS);
			if (str == nullptr)
				str = pembedded->proplist.get<char>(PR_MESSAGE_CLASS_A);
			if (str == nullptr)
				str = "IPM.Note";
			if (class_match_prefix(str,
			    "IPM.OLE.CLASS.{00061055-0000-0000-C000-000000000046}"))
				continue;
			if (!pembedded->proplist.has(proptag_xrt))
				continue;
			auto estr = oxcical_export_internal(method, tzid,
			      pembedded, log_id, pical, org_name,
			      id2user, alloc, get_propids);
			if (estr.size() > 0)
				return estr;
		}
	}

	return oxcical_export_valarm(*pmsg, *pcomponent, std::move(get_propids));
} catch (const std::bad_alloc &) {
	return "E-2097: ENOMEM";
}
#undef E_2201

bool oxcical_export(const MESSAGE_CONTENT *pmsg, const char *log_id, ical &pical,
    const char *org_name, EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
    cvt_id2user id2user)
{
	auto err = oxcical_export_internal(nullptr, nullptr, pmsg, log_id, pical,
	           org_name, std::move(id2user), alloc, std::move(get_propids));
	if (err.size() > 0) {
		mlog(LV_ERR, "%s", err.c_str());
		return false;
	}
	return true;
}

bool oxcical_export_freebusy(const char *user, const char *fbuser,
    time_t starttime, const time_t endtime,
    const std::vector<freebusy_event> &fbdata, ical &ic)
{
	ic.append_line("METHOD", "PUBLISH");
	ic.append_line("PRODID", "gromox-oxcical");
	ic.append_line("VERSION", "2.0");
	auto &com = ic.append_comp("VFREEBUSY");
	com.append_line("ORGANIZER", user);
	auto line = &com.append_line("ATTENDEE");
	line->append_param("PARTSTAT", "ACCEPTED");
	line->append_param("CUTYPE", "INDIVIDUAL");
	char tmp_value[334];
	snprintf(tmp_value, sizeof(tmp_value), "MAILTO:%s", fbuser);
	line->append_value(nullptr, tmp_value);
	ical_time itime1, itime2;
	if (!ical_utc_to_datetime(nullptr, starttime, &itime1))
		return false;
	append_dt(com, "DTSTART", itime1, false, nullptr);
	if (!ical_utc_to_datetime(nullptr, endtime, &itime1))
		return false;
	append_dt(com, "DTEND", itime1, false, nullptr);
	time_t nowtime = time(nullptr);
	if (!ical_utc_to_datetime(nullptr, nowtime, &itime1))
		return false;
	append_dt(com, "DTSTAMP", itime1, false, nullptr);
	if (fbdata.size() == 0)
		return true;
	for (const auto &event : fbdata) {
		line = &com.append_line("FREEBUSY");
		switch (event.busy_status) {
		case olFree:
			line->append_param("FBTYPE", "FREE");
			break;
		case olTentative:
			line->append_param("FBTYPE", "BUSY-TENTATIVE");
			break;
		default:
			line->append_param("FBTYPE", "BUSY");
			break;
		}
		if (!ical_utc_to_datetime(nullptr, event.start_time, &itime1) ||
		    !ical_utc_to_datetime(nullptr, event.end_time, &itime2))
			return false;
		char start[17], end[17];
		sprintf_dtutc(start, std::size(start), itime1);
		sprintf_dtutc(end, std::size(end), itime2);
		line->append_value(nullptr, start + "/"s + end);
	}
	return true;
}
