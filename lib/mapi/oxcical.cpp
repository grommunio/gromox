// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2022 grommunio GmbH
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
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/ical.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/oxcical.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#define MAX_TZRULE_NUMBER						128

#define MAX_TZDEFINITION_LENGTH					(68*MAX_TZRULE_NUMBER+270)

using namespace gromox;
using propididmap_t = std::unordered_map<uint16_t, uint16_t>;
using namemap = std::unordered_map<int, PROPERTY_NAME>;
using event_list_t = std::vector<std::shared_ptr<ical_component>>;
using uidxevent_list_t = std::unordered_map<std::string, event_list_t>;
using message_ptr = std::unique_ptr<MESSAGE_CONTENT, mc_delete>;

namespace gromox {
bool g_oxcical_allday_ymd = true;
}

static constexpr char
	PidNameKeywords[] = "Keywords",
	PidNameLocationUrl[] = "urn:schemas:calendar:locationurl";
static constexpr size_t namemap_limit = 0x1000;
static constexpr char EncodedGlobalId_hex[] =
	"040000008200E00074C5B7101A82E008";
static constexpr uint32_t indet_rendering_pos = UINT32_MAX;
static constexpr char fmt_date[] = "%04d%02d%02d",
	fmt_datetimelcl[] = "%04d%02d%02dT%02d%02d%02d",
	fmt_datetimeutc[] = "%04d%02d%02dT%02d%02d%02dZ";

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

static BOOL oxcical_parse_vtsubcomponent(const ical_component &sub,
	int32_t *pbias, int16_t *pyear,
	SYSTEMTIME *pdate)
{
	int hour;
	int minute;
	int dayofweek;
	int weekorder;
	ICAL_TIME itime;
	const char *pvalue;
	const char *pvalue1;
	const char *pvalue2;
	
	memset(pdate, 0, sizeof(SYSTEMTIME));
	auto piline = sub.get_line("TZOFFSETTO");
	if (piline == nullptr)
		return FALSE;
	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return FALSE;
	if (!ical_parse_utc_offset(pvalue, &hour, &minute))
		return FALSE;
	*pbias = 60*hour + minute;
	piline = sub.get_line("DTSTART");
	if (piline == nullptr)
		return FALSE;
	if (piline->get_first_paramval("TZID") != nullptr)
		return FALSE;
	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return FALSE;
	bool b_utc;
	if (!ical_parse_datetime(pvalue, &b_utc, &itime) || b_utc)
		return FALSE;
	*pyear = itime.year;
	pdate->hour = itime.hour;
	pdate->minute = itime.minute;
	pdate->second = itime.second;
	piline = sub.get_line("RRULE");
	if (NULL != piline) {
		pvalue = piline->get_first_subvalue_by_name("FREQ");
		if (pvalue == nullptr || strcasecmp(pvalue, "YEARLY") != 0)
			return FALSE;
		pvalue = piline->get_first_subvalue_by_name("BYDAY");
		pvalue1 = piline->get_first_subvalue_by_name("BYMONTHDAY");
		if ((pvalue == nullptr && pvalue1 == nullptr) ||
		    (pvalue != nullptr && pvalue1 != nullptr))
			return FALSE;
		pvalue2 = piline->get_first_subvalue_by_name("BYMONTH");
		if (NULL == pvalue2) {
			pdate->month = itime.month;
		} else {
			pdate->month = strtol(pvalue2, nullptr, 0);
			if (pdate->month < 1 || pdate->month > 12)
				return FALSE;
		}
		if (NULL != pvalue) {
			pdate->year = 0;
			if (!ical_parse_byday(pvalue, &dayofweek, &weekorder))
				return FALSE;
			if (weekorder == -1)
				weekorder = 5;
			if (weekorder > 5 || weekorder < 1)
				return FALSE;
			pdate->dayofweek = dayofweek;
			pdate->day = weekorder;
		} else {
			pdate->year = 1;
			pdate->dayofweek = 0;
			pdate->day = strtol(pvalue1, nullptr, 0);
			if (abs(pdate->day) < 1 || abs(pdate->day) > 31)
				return FALSE;
		}
	} else {
		pdate->year = 0;
		pdate->month = itime.month;
		pdate->dayofweek = ical_get_dayofweek(
			itime.year, itime.month, itime.day);
		pdate->day = ical_get_monthweekorder(itime.day);
	}
	return TRUE;
}

static BOOL oxcical_parse_tzdefinition(const ical_component &vt,
	TIMEZONEDEFINITION *ptz_definition)
{
	int i;
	BOOL b_found;
	int32_t bias;
	int16_t year;
	SYSTEMTIME date;
	BOOL b_daylight;
	TZRULE *pstandard_rule;
	TZRULE *pdaylight_rule;
	
	ptz_definition->major = 2;
	ptz_definition->minor = 1;
	ptz_definition->reserved = 0x0002;
	auto piline = vt.get_line("TZID");
	if (piline == nullptr)
		return FALSE;
	ptz_definition->keyname = deconst(piline->get_first_subvalue());
	if (ptz_definition->keyname == nullptr)
		return FALSE;
	ptz_definition->crules = 0;
	for (const auto &pcomponent : vt.component_list) {
		if (strcasecmp(pcomponent->m_name.c_str(), "STANDARD") == 0)
			b_daylight = FALSE;
		else if (strcasecmp(pcomponent->m_name.c_str(), "DAYLIGHT") == 0)
			b_daylight = TRUE;
		else
			continue;
		if (!oxcical_parse_vtsubcomponent(*pcomponent, &bias, &year, &date))
			return FALSE;
		b_found = FALSE;
		for (i=0; i<ptz_definition->crules; i++) {
			if (year == ptz_definition->prules[i].year) {
				b_found = TRUE;
				break;
			}
		}
		if (!b_found) {
			if (ptz_definition->crules >= MAX_TZRULE_NUMBER)
				return FALSE;
			ptz_definition->crules ++;
			memset(ptz_definition->prules + i, 0, sizeof(TZRULE));
			ptz_definition->prules[i].major = 2;
			ptz_definition->prules[i].minor = 1;
			ptz_definition->prules[i].reserved = 0x003E;
			ptz_definition->prules[i].year = year;
		}
		if (b_daylight) {
			ptz_definition->prules[i].daylightbias = bias;
			ptz_definition->prules[i].daylightdate = date;
		} else {
			ptz_definition->prules[i].bias = bias;
			ptz_definition->prules[i].standarddate = date;
		}
	}
	if (ptz_definition->crules == 0)
		return FALSE;
	std::sort(ptz_definition->prules, ptz_definition->prules + ptz_definition->crules);
	pstandard_rule = NULL;
	pdaylight_rule = NULL;
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
		/* calculate the offset from DAYLIGHT to STANDARD */
		ptz_definition->prules[i].daylightbias -=
				ptz_definition->prules[i].bias;
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
	ptz_definition->prules[0].year = 1;
	return TRUE;
}

static void oxcical_convert_to_tzstruct(
	TIMEZONEDEFINITION *ptz_definition, TIMEZONESTRUCT *ptz_struct)
{
	int index;
	
	index = ptz_definition->crules - 1;
	memset(ptz_struct, 0, sizeof(TIMEZONESTRUCT));
	ptz_struct->bias = ptz_definition->prules[index].bias;
	ptz_struct->daylightbias = ptz_definition->prules[index].daylightbias;
	ptz_struct->standarddate = ptz_definition->prules[index].standarddate;
	ptz_struct->daylightdate = ptz_definition->prules[index].daylightdate;
	ptz_struct->standardyear = ptz_struct->standarddate.year;
	ptz_struct->daylightyear = ptz_struct->daylightdate.year;
}

static BOOL oxcical_tzdefinition_to_binary(
	TIMEZONEDEFINITION *ptz_definition,
	uint16_t tzrule_flags, BINARY *pbin)
{
	EXT_PUSH ext_push;
	
	if (!ext_push.init(pbin->pb, MAX_TZDEFINITION_LENGTH, 0))
		return false;
	for (size_t i = 0; i < ptz_definition->crules; ++i)
		ptz_definition->prules[i].flags = tzrule_flags;
	if (ext_push.p_tzdef(*ptz_definition) != EXT_ERR_SUCCESS)
		return FALSE;
	pbin->cb = ext_push.m_offset;
	return TRUE;
}

static BOOL oxcical_timezonestruct_to_binary(
	TIMEZONESTRUCT *ptzstruct, BINARY *pbin)
{
	EXT_PUSH ext_push;
	
	if (!ext_push.init(pbin->pb, 256, 0) ||
	    ext_push.p_tzstruct(*ptzstruct) != EXT_ERR_SUCCESS)
		return false;
	pbin->cb = ext_push.m_offset;
	return TRUE;
}

/* ptz_component can be NULL, represents UTC */
static BOOL oxcical_parse_rrule(const ical_component &tzcom,
    const ical_line &iline, uint16_t calendartype, time_t start_time,
    uint32_t duration_minutes, APPOINTMENT_RECUR_PAT *apr)
{
	time_t tmp_time;
	ICAL_TIME itime1;
	ICAL_RRULE irrule;
	const char *pvalue;
	uint32_t patterntype = 0;
	const ICAL_TIME *pitime;
	
	auto piline = &iline;
	if (piline->get_subval_list("BYYEARDAY") != nullptr ||
	    piline->get_subval_list("BYWEEKNO") != nullptr)
		return FALSE;
	auto psubval_list = piline->get_subval_list("BYMONTHDAY");
	if (psubval_list != nullptr && psubval_list->size() > 1)
		return FALSE;
	psubval_list = piline->get_subval_list("BYSETPOS");
	if (psubval_list != nullptr && psubval_list->size() > 1)
		return FALSE;
	psubval_list = piline->get_subval_list("BYSECOND");
	if (NULL != psubval_list) {
		if (psubval_list->size() > 1)
			return FALSE;
		pvalue = piline->get_first_subvalue_by_name("BYSECOND");
		if (pvalue != nullptr && strtol(pvalue, nullptr, 0) != start_time % 60)
			return FALSE;
	}
	if (!ical_parse_rrule(&tzcom, start_time, &piline->value_list, &irrule))
		return FALSE;
	auto b_exceptional = irrule.b_start_exceptional;
	if (b_exceptional && !irrule.iterate())
		return FALSE;
	auto itime_base = irrule.base_itime;
	auto itime_first = irrule.instance_itime;
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
	ical_itime_to_utc(&tzcom, itime, &tmp_time);
	apr->recur_pat.startdate = rop_util_unix_to_nttime(tmp_time) / 600000000;
	if (irrule.endless()) {
 SET_INFINITE:
		apr->recur_pat.endtype = ENDTYPE_NEVER_END;
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
				return FALSE;
			itime = itime1;
		}
		if (irrule.total_count != 0) {
			apr->recur_pat.endtype = ENDTYPE_AFTER_N_OCCURRENCES;
			apr->recur_pat.occurrencecount = irrule.total_count;
		} else {
			apr->recur_pat.endtype = ENDTYPE_AFTER_DATE;
			apr->recur_pat.occurrencecount = irrule.sequence();
		}
		if (b_exceptional)
			--apr->recur_pat.occurrencecount;
		pitime = irrule.get_until_itime();
		itime = pitime != nullptr ? *pitime : irrule.instance_itime;
		itime.hour = 0;
		itime.minute = 0;
		itime.second = 0;
		ical_itime_to_utc(&tzcom, itime, &tmp_time);
		apr->recur_pat.enddate = rop_util_unix_to_nttime(tmp_time) / 600000000;
	}
	switch (irrule.frequency) {
	case ical_frequency::second:
	case ical_frequency::minute:
	case ical_frequency::hour:
		return FALSE;
	case ical_frequency::day:
		if (piline->get_subval_list("BYDAY") != nullptr ||
		    piline->get_subval_list("BYMONTH") != nullptr ||
		    piline->get_subval_list("BYSETPOS") != nullptr)
			return FALSE;
		apr->recur_pat.recurfrequency = RECURFREQUENCY_DAILY;
		if (irrule.interval > 999)
			return FALSE;
		apr->recur_pat.period = irrule.interval * 1440;
		apr->recur_pat.firstdatetime = apr->recur_pat.startdate % apr->recur_pat.period;
		patterntype = PATTERNTYPE_DAY;
		break;
	case ical_frequency::week:
		if (piline->get_subval_list("BYMONTH") != nullptr ||
		    piline->get_subval_list("BYSETPOS") != nullptr)
			return FALSE;
		apr->recur_pat.recurfrequency = RECURFREQUENCY_WEEKLY;
		if (irrule.interval > 99)
			return FALSE;
		apr->recur_pat.period = irrule.interval;
		itime = itime_base;
		itime.hour = 0;
		itime.minute = 0;
		itime.second = 0;
		itime.leap_second = 0;
		ical_itime_to_utc(NULL, itime, &tmp_time);
		apr->recur_pat.firstdatetime =
			(rop_util_unix_to_nttime(tmp_time)/600000000)%
			(10080 * irrule.interval);
		patterntype = PATTERNTYPE_WEEK;
		if (irrule.check_bymask(RRULE_BY_DAY)) {
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
			return FALSE;
		apr->recur_pat.recurfrequency = RECURFREQUENCY_MONTHLY;
		if (irrule.interval > 99)
			return FALSE;
		apr->recur_pat.period = irrule.interval;
		memset(&itime, 0, sizeof(ICAL_TIME));
		itime.year = 1601;
		itime.month = ((itime_base.year - 1601) * 12 + itime_base.month - 1) %
		              irrule.interval + 1;
		itime.year += itime.month/12;
		itime.month = (itime.month - 1) % 12 + 1;
		itime.day = 1;
		memset(&itime1, 0, sizeof(ICAL_TIME));
		itime1.year = 1601;
		itime1.month = 1;
		itime1.day = 1;
		apr->recur_pat.firstdatetime = itime.delta_day(itime1) * 1440;
		if (irrule.check_bymask(RRULE_BY_DAY) &&
		    irrule.check_bymask(RRULE_BY_SETPOS)) {
			patterntype = PATTERNTYPE_MONTHNTH;
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
				return FALSE;
			else if (tmp_int == -1)
				tmp_int = 5;
			apr->recur_pat.pts.monthnth.recurnum = tmp_int;
		} else {
			if (irrule.check_bymask(RRULE_BY_DAY) ||
			    irrule.check_bymask(RRULE_BY_SETPOS))
				return FALSE;
			int tmp_int;
			patterntype = PATTERNTYPE_MONTH;
			pvalue = piline->get_first_subvalue_by_name("BYMONTHDAY");
			if (NULL == pvalue) {
				ical_utc_to_datetime(&tzcom, start_time, &itime);
				tmp_int = itime.day;
			} else {
				tmp_int = strtol(pvalue, nullptr, 0);
				if (tmp_int < -1)
					return FALSE;
				else if (tmp_int == -1)
					tmp_int = 31;
			}
			apr->recur_pat.pts.dayofmonth = tmp_int;
		}
		break;
	case ical_frequency::year:
		apr->recur_pat.recurfrequency = RECURFREQUENCY_YEARLY;
		if (irrule.interval > 8)
			return FALSE;
		apr->recur_pat.period = 12 * irrule.interval;
		memset(&itime, 0, sizeof(ICAL_TIME));
		itime.year = 1601;
		itime.month = (itime_first.month - 1) % (12 * irrule.interval) + 1;
		itime.year += itime.month/12;
		itime.month = (itime.month - 1) % 12 + 1;
		itime.day = 1;
		memset(&itime1, 0, sizeof(ICAL_TIME));
		itime1.year = 1601;
		itime1.month = 1;
		itime1.day = 1;
		apr->recur_pat.firstdatetime = itime.delta_day(itime1) * 1440;
		if (irrule.check_bymask(RRULE_BY_DAY) &&
		    irrule.check_bymask(RRULE_BY_SETPOS) &&
		    irrule.check_bymask(RRULE_BY_MONTH)) {
			if (irrule.check_bymask(RRULE_BY_MONTHDAY))
				return FALSE;
			patterntype = PATTERNTYPE_MONTHNTH;
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
				return FALSE;
			else if (tmp_int == -1)
				tmp_int = 5;
			apr->recur_pat.pts.monthnth.recurnum = tmp_int;
		} else {
			if (irrule.check_bymask(RRULE_BY_DAY) ||
			    irrule.check_bymask(RRULE_BY_SETPOS))
				return FALSE;
			int tmp_int;
			patterntype = PATTERNTYPE_MONTH;
			pvalue = piline->get_first_subvalue_by_name("BYMONTHDAY");
			if (NULL == pvalue) {
				ical_utc_to_datetime(&tzcom, start_time, &itime);
				tmp_int = itime.day;
			} else {
				tmp_int = strtol(pvalue, nullptr, 0);
				if (tmp_int < -1)
					return FALSE;
				else if (tmp_int == -1)
					tmp_int = 31;
			}
			apr->recur_pat.pts.dayofmonth = tmp_int;
		}
		break;
	}
	if (calendartype == CAL_HIJRI) {
		if (PATTERNTYPE_MONTH == patterntype) {
			patterntype = PATTERNTYPE_HJMONTH;
			calendartype = CAL_DEFAULT;
		} else if (PATTERNTYPE_MONTHNTH == patterntype) {
			patterntype = PATTERNTYPE_HJMONTHNTH;
			calendartype = CAL_DEFAULT;
		}
	}
	apr->recur_pat.patterntype = patterntype;
	apr->recur_pat.calendartype = calendartype;
	return TRUE;
}

static const ical_component *oxcical_find_vtimezone(const ical &pical, const char *tzid)
{
	const char *pvalue;
	
	for (const auto &pcomponent : pical.component_list) {
		if (strcasecmp(pcomponent->m_name.c_str(), "VTIMEZONE") != 0)
			continue;
		auto piline = pcomponent->get_line("TZID");
		if (piline == nullptr)
			continue;
		pvalue = piline->get_first_subvalue();
		if (pvalue == nullptr)
			continue;
		if (strcasecmp(pvalue, tzid) == 0)
			return pcomponent.get();
	}
	return NULL;
}

static BOOL oxcical_parse_tzdisplay(BOOL b_dtstart, const ical_component &tzcom,
    namemap &phash, uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	TIMEZONEDEFINITION tz_definition;
	TZRULE rules_buff[MAX_TZRULE_NUMBER];
	uint8_t bin_buff[MAX_TZDEFINITION_LENGTH];
	
	tz_definition.prules = rules_buff;
	if (!oxcical_parse_tzdefinition(tzcom, &tz_definition))
		return FALSE;
	tmp_bin.pb = bin_buff;
	tmp_bin.cb = 0;
	if (!oxcical_tzdefinition_to_binary(&tz_definition,
	    TZRULE_FLAG_EFFECTIVE_TZREG, &tmp_bin))
		return FALSE;
	PROPERTY_NAME propname = {MNID_ID, PSETID_APPOINTMENT, b_dtstart ?
		PidLidAppointmentTimeZoneDefinitionStartDisplay :
		PidLidAppointmentTimeZoneDefinitionEndDisplay};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	if (pmsg->proplist.set(PROP_TAG(PT_BINARY, *plast_propid), &tmp_bin) != 0)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_recurring_timezone(const ical_component &tzcom,
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
		return FALSE;
	auto piline = tzcom.get_line("TZID");
	if (piline == nullptr)
		return FALSE;
	ptzid = piline->get_first_subvalue();
	if (ptzid == nullptr)
		return FALSE;
	PROPERTY_NAME propname = {MNID_ID, PSETID_APPOINTMENT, PidLidTimeZoneDescription};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	if (pmsg->proplist.set(PROP_TAG(PT_UNICODE, *plast_propid), ptzid) != 0)
		return FALSE;
	(*plast_propid) ++;
	oxcical_convert_to_tzstruct(&tz_definition, &tz_struct);
	tmp_bin.pb = bin_buff;
	tmp_bin.cb = 0;
	if (!oxcical_timezonestruct_to_binary(&tz_struct, &tmp_bin))
		return FALSE;
	propname = {MNID_ID, PSETID_APPOINTMENT, PidLidTimeZoneStruct};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	if (pmsg->proplist.set(PROP_TAG(PT_BINARY, *plast_propid), &tmp_bin) != 0)
		return FALSE;
	(*plast_propid) ++;
	tmp_bin.pb = bin_buff;
	tmp_bin.cb = 0;
	if (!oxcical_tzdefinition_to_binary(&tz_definition,
	    TZRULE_FLAG_EFFECTIVE_TZREG | TZRULE_FLAG_RECUR_CURRENT_TZREG, &tmp_bin))
		return FALSE;
	propname = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentTimeZoneDefinitionRecur};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	if (pmsg->proplist.set(PROP_TAG(PT_BINARY, *plast_propid), &tmp_bin) != 0)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_proposal(namemap &phash,
	uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	uint8_t tmp_byte;
	PROPERTY_NAME pn = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentCounterProposal};
	if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
		return FALSE;
	tmp_byte = 1;
	if (pmsg->proplist.set(PROP_TAG(PT_BOOLEAN, *plast_propid), &tmp_byte) != 0)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
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

static BOOL oxcical_parse_recipients(const ical_component &main_ev,
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
	
	auto pmessage_class = pmsg->proplist.get<char>(PR_MESSAGE_CLASS);
	if (pmessage_class == nullptr)
		pmessage_class = pmsg->proplist.get<char>(PR_MESSAGE_CLASS_A);
	/* ignore ATTENDEE when METHOD is "PUBLIC" */
	if (pmessage_class == nullptr ||
	    strcasecmp(pmessage_class, "IPM.Appointment") == 0)
		return TRUE;
	prcpts = tarray_set_init();
	if (prcpts == nullptr)
		return FALSE;
	tmp_byte = 0;
	message_content_set_rcpts_internal(pmsg, prcpts);
	for (const auto &line : main_ev.line_list) {
		auto piline = &line;
		if (strcasecmp(piline->m_name.c_str(), "ATTENDEE") != 0)
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
			return FALSE;
		if (pproplist->set(PR_ADDRTYPE, "SMTP") != 0 ||
		    pproplist->set(PR_EMAIL_ADDRESS, paddress) != 0 ||
		    pproplist->set(PR_SMTP_ADDRESS, paddress) != 0)
			return FALSE;
		if (pdisplay_name == nullptr)
			pdisplay_name = paddress;
		if (pproplist->set(PR_DISPLAY_NAME, pdisplay_name) != 0 ||
		    pproplist->set(PR_TRANSMITABLE_DISPLAY_NAME, pdisplay_name) != 0)
			return FALSE;
		tmp_bin.pb = tmp_buff;
		tmp_bin.cb = 0;
		auto dtypx = DT_MAILUSER;
		if (!username_to_entryid(paddress, pdisplay_name, &tmp_bin, &dtypx) ||
		    pproplist->set(PR_ENTRYID, &tmp_bin) != 0 ||
		    pproplist->set(PR_RECIPIENT_ENTRYID, &tmp_bin) != 0 ||
		    pproplist->set(PR_RECORD_KEY, &tmp_bin) != 0)
			return FALSE;
		tmp_int32 = role_to_rcpttype(prole, cutype);
		if (pproplist->set(PR_RECIPIENT_TYPE, &tmp_int32) != 0)
			return FALSE;
		tmp_int32 = dtypx == DT_DISTLIST ? MAPI_DISTLIST : MAPI_MAILUSER;
		if (pproplist->set(PR_OBJECT_TYPE, &tmp_int32) != 0)
			return FALSE;
		tmp_int32 = static_cast<uint32_t>(dtypx);
		if (pproplist->set(PR_DISPLAY_TYPE, &tmp_int32) != 0)
			return FALSE;
		tmp_byte = 1;
		if (pproplist->set(PR_RESPONSIBILITY, &tmp_byte) != 0)
			return FALSE;
		tmp_int32 = recipSendable;
		if (pproplist->set(PR_RECIPIENT_FLAGS, &tmp_int32) != 0)
			return FALSE;
	}
	/*
	 * XXX: Value of tmp_byte is unclear, but it appears it coincides with
	 * the presence of any recipients.
	 */
	if (pmsg->proplist.set(PR_RESPONSE_REQUESTED, &tmp_byte) != 0 ||
	    pmsg->proplist.set(PR_REPLY_REQUESTED, &tmp_byte) != 0)
		return FALSE;
	return TRUE;
}

static BOOL oxcical_parse_categories(const ical_component &main_event,
   namemap &phash, uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	auto piline = main_event.get_line("CATEGORIES");
	if (piline == nullptr)
		return TRUE;

	char *tmp_buff[128];
	STRING_ARRAY strings_array;
	
	if (piline->value_list.size() == 0)
		return TRUE;
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
			return FALSE;
		if (pmsg->proplist.set(PROP_TAG(PT_MV_UNICODE, *plast_propid), &strings_array) != 0)
			return FALSE;
		(*plast_propid) ++;
	}
	return TRUE;
}

static BOOL oxcical_parse_class(const ical_component &main_event,
    MESSAGE_CONTENT *pmsg)
{
	auto piline = main_event.get_line("CLASS");
	if (piline == nullptr) {
		uint32_t v = SENSITIVITY_NONE;
		if (pmsg->proplist.set(PR_SENSITIVITY, &v) != 0)
			return FALSE;
		return TRUE;
	}

	uint32_t tmp_int32;
	const char *pvalue;
	
	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return TRUE;
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
		return TRUE;
	if (pmsg->proplist.set(PR_SENSITIVITY, &tmp_int32) != 0)
		return FALSE;
	return TRUE;
}

static BOOL oxcical_parse_body(const ical_component &main_event,
    const char *method, MESSAGE_CONTENT *pmsg)
{
	const char *linetype = "DESCRIPTION";
	if (method != nullptr && (strcasecmp(method, "reply") == 0 ||
	    strcasecmp(method, "counter") == 0))
		linetype = "COMMENT";
	auto piline = main_event.get_line(linetype);
	if (piline == nullptr)
		return TRUE;

	const char *pvalue;
	
	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return TRUE;
	if (pmsg->proplist.set(PR_BODY, pvalue) != 0)
		return FALSE;
	return TRUE;
}

static BOOL oxcical_parse_html(const ical_component &main_event,
    MESSAGE_CONTENT *pmsg)
{
	auto piline = main_event.get_line("X-ALT-DESC");
	if (piline == nullptr)
		return TRUE;
	auto pvalue = piline->get_first_paramval("FMTTYPE");
	if (pvalue == nullptr || strcasecmp(pvalue, "text/html") != 0)
		return TRUE;

	BINARY tmp_bin;
	uint32_t tmp_int32;
	
	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return TRUE;
	tmp_bin.cb = strlen(pvalue);
	tmp_bin.pc = deconst(pvalue);
	if (pmsg->proplist.set(PR_HTML, &tmp_bin) != 0)
		return FALSE;
	tmp_int32 = 65001;
	if (pmsg->proplist.set(PR_INTERNET_CPID, &tmp_int32) != 0)
		return FALSE;
	return TRUE;
}

static BOOL oxcical_parse_dtstamp(const ical_component &main_event,
    const char *method, namemap &phash,
	uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	auto piline = main_event.get_line("DTSTAMP");
	if (piline == nullptr)
		return TRUE;

	time_t tmp_time;
	uint64_t tmp_int64;
	const char *pvalue;
	
	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return TRUE;
	if (!ical_datetime_to_utc(nullptr, pvalue, &tmp_time))
		return TRUE;
	PROPERTY_NAME propname = {MNID_ID, PSETID_MEETING};
	propname.lid = (method != nullptr && (strcasecmp(method, "REPLY") == 0 ||
	                strcasecmp(method, "COUNTER") == 0)) ?
	               PidLidAttendeeCriticalChange : PidLidOwnerCriticalChange;
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	tmp_int64 = rop_util_unix_to_nttime(tmp_time);
	if (pmsg->proplist.set(PROP_TAG(PT_SYSTIME, *plast_propid), &tmp_int64) != 0)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_start_end(BOOL b_start, BOOL b_proposal,
    const ical_component &pmain_event, time_t unix_time,
    namemap &phash, uint16_t *plast_propid,  MESSAGE_CONTENT *pmsg)
{
	uint64_t tmp_int64;
	
	tmp_int64 = rop_util_unix_to_nttime(unix_time);
	if (b_proposal) {
		PROPERTY_NAME pn = {MNID_ID, PSETID_APPOINTMENT, b_start ?
			PidLidAppointmentProposedStartWhole :
			PidLidAppointmentProposedEndWhole};
		if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
			return FALSE;
		if (pmsg->proplist.set(PROP_TAG(PT_SYSTIME, *plast_propid), &tmp_int64) != 0)
			return FALSE;
		(*plast_propid) ++;
	}
	if (!b_proposal ||
	    (pmain_event.get_line("X-MS-OLK-ORIGINALEND") == nullptr &&
	    pmain_event.get_line("X-MS-OLK-ORIGINALSTART") == nullptr)) {
		PROPERTY_NAME pn = {MNID_ID, PSETID_APPOINTMENT, b_start ?
			PidLidAppointmentStartWhole : PidLidAppointmentEndWhole};
		if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
			return FALSE;
		if (pmsg->proplist.set(PROP_TAG(PT_SYSTIME, *plast_propid), &tmp_int64) != 0)
			return FALSE;
		(*plast_propid) ++;
	}
	return TRUE;
}

static BOOL oxcical_parse_subtype(namemap &phash, uint16_t *plast_propid,
    MESSAGE_CONTENT *pmsg, EXCEPTIONINFO *pexception)
{
	uint8_t tmp_byte;
	PROPERTY_NAME pn = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentSubType};
	if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
		return FALSE;
	tmp_byte = 1;
	if (pmsg->proplist.set(PROP_TAG(PT_BOOLEAN, *plast_propid), &tmp_byte) != 0)
		return FALSE;
	(*plast_propid) ++;
	if (NULL != pexception) {
		pexception->overrideflags |= ARO_SUBTYPE;
		pexception->subtype = 1;
	}
	return TRUE;
}

static BOOL oxcical_parse_dates(const ical_component *ptz_component,
    const ical_line &iline, uint32_t *pcount, uint32_t *pdates)
{
	bool b_utc;
	ICAL_TIME itime;
	time_t tmp_time;
	uint32_t tmp_date;
	const char *pvalue;
	
	auto piline = &iline;
	if (piline->value_list.size() == 0)
		return TRUE;
	*pcount = 0;
	auto &pivalue = piline->value_list.front();
	pvalue = piline->get_first_paramval("VALUE");
	if (NULL == pvalue || 0 == strcasecmp(pvalue, "DATE-TIME")) {
		for (const auto &pnv2 : pivalue.subval_list) {
			if (pnv2.empty())
				continue;
			if (!ical_parse_datetime(pnv2.c_str(), &b_utc, &itime))
				continue;
			if (b_utc && ptz_component != nullptr) {
				ical_itime_to_utc(NULL, itime, &tmp_time);
				ical_utc_to_datetime(ptz_component, tmp_time, &itime);
			}
			itime.hour = 0;
			itime.minute = 0;
			itime.second = 0;
			ical_itime_to_utc(NULL, itime, &tmp_time);
			tmp_date = rop_util_unix_to_nttime(tmp_time)/600000000;
			for (size_t i = 0; i < *pcount; ++i)
				if (tmp_date == pdates[i])
					return TRUE;
			pdates[*pcount] = tmp_date;
			(*pcount) ++;
			if (*pcount >= 1024)
				return TRUE;
		}
	} else if (0 == strcasecmp(pvalue, "DATE")) {
		for (const auto &pnv2 : pivalue.subval_list) {
			if (pnv2.empty())
				continue;
			memset(&itime, 0, sizeof(ICAL_TIME));
			if (!ical_parse_date(pnv2.c_str(), &itime.year, &itime.month, &itime.day))
				continue;
			ical_itime_to_utc(NULL, itime, &tmp_time);
			pdates[*pcount] = rop_util_unix_to_nttime(tmp_time)/600000000;
			(*pcount) ++;
			if (*pcount >= 1024)
				return TRUE;
		}
	} else {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_parse_duration(uint32_t minutes, namemap &phash,
    uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	PROPERTY_NAME pn = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentDuration};
	if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
		return FALSE;
	if (pmsg->proplist.set(PROP_TAG(PT_LONG, *plast_propid), &minutes) != 0)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_dtvalue(const ical_component *ptz_component,
    const ical_line &piline, bool *b_utc, ICAL_TIME *pitime,
    time_t *putc_time)
{
	auto pvalue = piline.get_first_subvalue();
	if (pvalue == nullptr)
		return FALSE;
	time_t dummy_time;
	if (putc_time == nullptr)
		/* Caller does not care about result */
		putc_time = &dummy_time;
	auto pvalue1 = piline.get_first_paramval("VALUE");
	if (NULL == pvalue1 || 0 == strcasecmp(pvalue1, "DATE-TIME")) {
		if (!ical_parse_datetime(pvalue, b_utc, pitime)) {
			if (pvalue1 == nullptr)
				goto PARSE_DATE_VALUE;
			return FALSE;
		}
		if (*b_utc) {
			if (!ical_itime_to_utc(nullptr, *pitime, putc_time))
				return FALSE;
		} else {
			if (!ical_itime_to_utc(ptz_component,
			    *pitime, putc_time))
				return FALSE;
		}
	} else if (0 == strcasecmp(pvalue1, "DATE")) {
 PARSE_DATE_VALUE:
		memset(pitime, 0, sizeof(ICAL_TIME));
		if (!ical_parse_date(pvalue, &pitime->year,
		    &pitime->month, &pitime->day))
			return FALSE;
		if (!ical_itime_to_utc(ptz_component, *pitime, putc_time))
			return FALSE;
		*b_utc = false;
	} else {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_parse_uid(const ical_component &main_event,
    ICAL_TIME effective_itime, EXT_BUFFER_ALLOC alloc, namemap &phash,
    uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	auto piline = main_event.get_line("UID");
	if (piline == nullptr)
		return TRUE;

	BINARY tmp_bin;
	EXT_PULL ext_pull;
	EXT_PUSH ext_push;
	const char *pvalue;
	char tmp_buff[1024];
	GLOBALOBJECTID globalobjectid;
	
	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return TRUE;
	auto tmp_len = strlen(pvalue);
	if (strncasecmp(pvalue, EncodedGlobalId_hex, 32) == 0 &&
	    decode_hex_binary(pvalue, tmp_buff, arsizeof(tmp_buff))) {
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
		return FALSE;
	memcpy(globalobjectid.data.pb, ThirdPartyGlobalId, 12);
	memcpy(globalobjectid.data.pb + 12, pvalue, tmp_len);
 MAKE_GLOBALOBJID:
	if (!ext_push.init(tmp_buff, 1024, 0) ||
	    ext_push.p_goid(globalobjectid) != EXT_ERR_SUCCESS)
		return false;
	tmp_bin.cb = ext_push.m_offset;
	tmp_bin.pc = tmp_buff;
	PROPERTY_NAME propname = {MNID_ID, PSETID_MEETING, PidLidGlobalObjectId};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	if (pmsg->proplist.set(PROP_TAG(PT_BINARY, *plast_propid), &tmp_bin) != 0)
		return FALSE;
	(*plast_propid) ++;
	globalobjectid.year = 0;
	globalobjectid.month = 0;
	globalobjectid.day = 0;
	if (!ext_push.init(tmp_buff, 1024, 0) ||
	    ext_push.p_goid(globalobjectid) != EXT_ERR_SUCCESS)
		return false;
	tmp_bin.cb = ext_push.m_offset;
	tmp_bin.pc = tmp_buff;
	propname = {MNID_ID, PSETID_MEETING, PidLidCleanGlobalObjectId};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	if (pmsg->proplist.set(PROP_TAG(PT_BINARY, *plast_propid), &tmp_bin) != 0)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_location(const ical_component &main_event,
    namemap &phash, uint16_t *plast_propid, EXT_BUFFER_ALLOC alloc,
	MESSAGE_CONTENT *pmsg, EXCEPTIONINFO *pexception,
	EXTENDEDEXCEPTION *pext_exception)
{
	auto piline = main_event.get_line("LOCATION");
	if (piline == nullptr)
		return TRUE;

	int i;
	int tmp_len;
	const char *pvalue;
	char tmp_buff[1024];
	
	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return TRUE;
	tmp_len = strlen(pvalue);
	if (tmp_len >= 1024)
		return TRUE;
	memcpy(tmp_buff, pvalue, tmp_len + 1);
	if (!utf8_truncate(tmp_buff, 255))
		return TRUE;
	tmp_len = strlen(tmp_buff);
	for (i=0; i<tmp_len; i++) {
		if ('\r' == tmp_buff[i] || '\n' == tmp_buff[i]) {
			memmove(tmp_buff + i, tmp_buff + i + 1, tmp_len - i);
			tmp_len --;
		}
	}
	PROPERTY_NAME propname = {MNID_ID, PSETID_APPOINTMENT, PidLidLocation};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	if (pmsg->proplist.set(PROP_TAG(PT_UNICODE, *plast_propid), tmp_buff) != 0)
		return FALSE;
	(*plast_propid) ++;
	pvalue = piline->get_first_paramval("ALTREP");
	if (pvalue == nullptr)
		return TRUE;
	propname = {MNID_STRING, PS_PUBLIC_STRINGS, 0, deconst(PidNameLocationUrl)};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	if (pmsg->proplist.set(PROP_TAG(PT_UNICODE, *plast_propid), pvalue) != 0)
		return FALSE;
	(*plast_propid) ++;
	if (NULL != pexception && NULL != pext_exception) {
		pexception->overrideflags |= ARO_LOCATION;
		pexception->location = static_cast<char *>(alloc(tmp_len + 1));
		if (pexception->location == nullptr)
			return FALSE;
		strcpy(pexception->location, tmp_buff);
		pext_exception->location = static_cast<char *>(alloc(tmp_len + 1));
		if (pext_exception->location == nullptr)
			return FALSE;
		strcpy(pext_exception->location, tmp_buff);
	}
	return TRUE;
}

static BOOL oxcical_parse_organizer(const ical_component &main_event,
	USERNAME_TO_ENTRYID username_to_entryid, MESSAGE_CONTENT *pmsg)
{
	auto piline = main_event.get_line("ORGANIZER");
	if (piline == nullptr)
		return TRUE;
	BINARY tmp_bin;
	uint8_t tmp_buff[1024];
	const char *paddress;
	const char *pdisplay_name;
	
	auto pvalue = pmsg->proplist.get<char>(PR_MESSAGE_CLASS);
	if (pvalue == nullptr)
		pvalue = pmsg->proplist.get<char>(PR_MESSAGE_CLASS_A);
	if (pvalue == nullptr)
		return FALSE;
	/* ignore ORGANIZER when METHOD is "REPLY" OR "COUNTER" */
	if (strncasecmp(pvalue, "IPM.Schedule.Meeting.Resp.", 26) == 0)
		return TRUE;
	paddress = piline->get_first_subvalue();
	if (NULL != paddress) {
		if (strncasecmp(paddress, "MAILTO:", 7) == 0)
			paddress += 7;
		else
			paddress = NULL;
	}
	pdisplay_name = piline->get_first_paramval("CN");
	if (pdisplay_name != nullptr)
		if (pmsg->proplist.set(PR_SENT_REPRESENTING_NAME, pdisplay_name) != 0 ||
		    pmsg->proplist.set(PR_SENDER_NAME, pdisplay_name) != 0)
			return FALSE;
	if (paddress == nullptr)
		return TRUE;
	tmp_bin.pb = tmp_buff;
	tmp_bin.cb = 0;
	if (!username_to_entryid(paddress, pdisplay_name, &tmp_bin, nullptr))
		return FALSE;
	if (pmsg->proplist.set(PR_SENT_REPRESENTING_ADDRTYPE, "SMTP") != 0 ||
	    pmsg->proplist.set(PR_SENT_REPRESENTING_EMAIL_ADDRESS, paddress) != 0 ||
	    pmsg->proplist.set(PR_SENT_REPRESENTING_SMTP_ADDRESS, paddress) != 0 ||
	    pmsg->proplist.set(PR_SENT_REPRESENTING_ENTRYID, &tmp_bin) != 0 ||
	    pmsg->proplist.set(PR_SENDER_ADDRTYPE, "SMTP") != 0 ||
	    pmsg->proplist.set(PR_SENDER_EMAIL_ADDRESS, paddress) != 0 ||
	    pmsg->proplist.set(PR_SENDER_SMTP_ADDRESS, paddress) != 0 ||
	    pmsg->proplist.set(PR_SENDER_ENTRYID, &tmp_bin) != 0)
		return FALSE;
	return TRUE;
}

static BOOL oxcical_parse_sequence(const ical_component &main_event,
    namemap &phash, uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	auto piline = main_event.get_line("X-MICROSOFT-CDO-APPT-SEQUENCE");
	if (piline == nullptr)
		piline = main_event.get_line("SEQUENCE");
	if (piline == nullptr)
		return TRUE;

	const char *pvalue;
	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return TRUE;
	uint32_t tmp_int32 = strtol(pvalue, nullptr, 0);
	PROPERTY_NAME pn = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentSequence};
	if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
		return FALSE;
	if (pmsg->proplist.set(PROP_TAG(PT_LONG, *plast_propid), &tmp_int32) != 0)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
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

static BOOL oxcical_set_busystatus(ol_busy_status busy_status,
    uint32_t pidlid, namemap &phash, uint16_t *plast_propid,
    MESSAGE_CONTENT *pmsg, EXCEPTIONINFO *pexception)
{
	if (busy_status == olIndeterminate)
		return TRUE;
	PROPERTY_NAME pn = {MNID_ID, PSETID_APPOINTMENT, pidlid};
	if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
		return FALSE;
	if (pmsg->proplist.set(PROP_TAG(PT_LONG, *plast_propid), &busy_status) != 0)
		return FALSE;
	(*plast_propid) ++;
	if (NULL != pexception) {
		pexception->overrideflags |= ARO_BUSYSTATUS;
		pexception->busystatus = busy_status;
	}
	return TRUE;
}

static BOOL oxcical_parse_summary(const ical_component &main_event,
    MESSAGE_CONTENT *pmsg, EXT_BUFFER_ALLOC alloc, EXCEPTIONINFO *pexception,
	EXTENDEDEXCEPTION *pext_exception)
{
	auto piline = main_event.get_line("SUMMARY");
	if (piline == nullptr)
		return TRUE;
	int i;
	int tmp_len;
	const char *pvalue;
	char tmp_buff[1024];
	
	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return TRUE;
	tmp_len = strlen(pvalue);
	if (tmp_len >= 1024)
		return TRUE;
	memcpy(tmp_buff, pvalue, tmp_len + 1);
	if (!utf8_truncate(tmp_buff, 255))
		return TRUE;
	tmp_len = strlen(tmp_buff);
	for (i=0; i<tmp_len; i++) {
		if ('\r' == tmp_buff[i] || '\n' == tmp_buff[i]) {
			memmove(tmp_buff + i, tmp_buff + i + 1, tmp_len - i);
			tmp_len --;
		}
	}
	if (pmsg->proplist.set(PR_SUBJECT, tmp_buff) != 0)
		return FALSE;
	if (NULL != pexception && NULL != pext_exception) {
		pexception->overrideflags |= ARO_SUBJECT;
		pexception->subject = static_cast<char *>(alloc(tmp_len + 1));
		if (pexception->subject == nullptr)
			return FALSE;
		strcpy(pexception->subject, tmp_buff);
		pext_exception->subject = static_cast<char *>(alloc(tmp_len + 1));
		if (pext_exception->subject == nullptr)
			return FALSE;
		strcpy(pext_exception->subject, tmp_buff);
	}
	return TRUE;
}

static BOOL oxcical_parse_ownerapptid(const ical_component &main_event,
    MESSAGE_CONTENT *pmsg)
{
	auto piline = main_event.get_line("X-MICROSOFT-CDO-OWNERAPPTID");
	if (piline == nullptr)
		return TRUE;
	const char *pvalue;
	
	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return TRUE;
	uint32_t tmp_int32 = strtol(pvalue, nullptr, 0);
	if (pmsg->proplist.set(PR_OWNER_APPT_ID, &tmp_int32) != 0)
		return FALSE;
	return TRUE;
}

static BOOL oxcical_parse_recurrence_id(const ical_component *ptz_component,
    const ical_line &piline, namemap &phash,
    uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	time_t tmp_time;
	ICAL_TIME itime;
	uint64_t tmp_int64;
	bool b_utc;
	
	if (!oxcical_parse_dtvalue(ptz_component,
	    piline, &b_utc, &itime, &tmp_time))
		return FALSE;
	PROPERTY_NAME pn = {MNID_ID, PSETID_APPOINTMENT, PidLidExceptionReplaceTime};
	if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
		return FALSE;
	tmp_int64 = rop_util_unix_to_nttime(tmp_time);
	if (pmsg->proplist.set(PROP_TAG(PT_SYSTIME, *plast_propid), &tmp_int64) != 0)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_disallow_counter(const ical_component &main_event,
    namemap &phash, uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	auto piline = main_event.get_line("X-MICROSOFT-DISALLOW-COUNTER");
	if (piline == nullptr)
		return TRUE;
	uint8_t tmp_byte;
	const char *pvalue;
	
	pvalue = piline->get_first_subvalue();
	if (pvalue == nullptr)
		return TRUE;
	if (strcasecmp(pvalue, "TRUE") == 0)
		tmp_byte = 1;
	else if (strcasecmp(pvalue, "FALSE") == 0)
		tmp_byte = 0;
	else
		return TRUE;

	PROPERTY_NAME pn = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentNotAllowPropose};
	if (namemap_add(phash, *plast_propid, std::move(pn)) != 0)
		return FALSE;
	if (pmsg->proplist.set(PROP_TAG(PT_BOOLEAN, *plast_propid), &tmp_byte) != 0)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static uint32_t aptrecur_to_recurtype(const APPOINTMENT_RECUR_PAT &apr)
{
	switch (apr.recur_pat.recurfrequency) {
	case RECURFREQUENCY_DAILY: return rectypeDaily;
	case RECURFREQUENCY_WEEKLY: return rectypeWeekly;
	case RECURFREQUENCY_MONTHLY: return rectypeMonthly;
	case RECURFREQUENCY_YEARLY: return rectypeYearly;
	default: return rectypeNone;
	}
}

static BOOL oxcical_parse_appointment_recurrence(APPOINTMENT_RECUR_PAT *apr,
    namemap &phash, uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	uint64_t nt_time;
	EXT_PUSH ext_push;
	
	if (!ext_push.init(nullptr, 0, EXT_FLAG_UTF16) ||
	    ext_push.p_apptrecpat(*apr) != EXT_ERR_SUCCESS)
		return FALSE;
	tmp_bin.cb = ext_push.m_offset;
	tmp_bin.pb = ext_push.m_udata;
	PROPERTY_NAME propname = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentRecur};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	if (pmsg->proplist.set(PROP_TAG(PT_BINARY, *plast_propid), &tmp_bin) != 0)
		return FALSE;
	(*plast_propid) ++;
	propname = {MNID_ID, PSETID_APPOINTMENT, PidLidRecurring};
	uint8_t flag = 1;
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0 ||
	    pmsg->proplist.set(PROP_TAG(PT_BOOLEAN, *plast_propid), &flag) != 0)
		return false;
	++*plast_propid;
	propname = {MNID_ID, PSETID_APPOINTMENT, PidLidRecurrenceType};
	uint32_t num = aptrecur_to_recurtype(*apr);
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0 ||
	    pmsg->proplist.set(PROP_TAG(PT_LONG, *plast_propid), &num) != 0)
		return false;
	++*plast_propid;
	nt_time = apr->recur_pat.endtype == ENDTYPE_NEVER_END ||
	          apr->recur_pat.endtype == ENDTYPE_NEVER_END1 ?
	          1525076159 : /* 31 August 4500, 11:59 P.M */
	          apr->recur_pat.enddate;
	nt_time *= 600000000;
	propname = {MNID_ID, PSETID_APPOINTMENT, PidLidClipEnd};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	if (pmsg->proplist.set(PROP_TAG(PT_SYSTIME, *plast_propid), &nt_time) != 0)
		return FALSE;
	(*plast_propid) ++;
	nt_time = apr->recur_pat.startdate;
	nt_time *= 600000000;
	propname = {MNID_ID, PSETID_APPOINTMENT, PidLidClipStart};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	if (pmsg->proplist.set(PROP_TAG(PT_SYSTIME, *plast_propid), &nt_time) != 0)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
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

static BOOL oxcical_fetch_propname(MESSAGE_CONTENT *pmsg, namemap &phash,
    EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids)
{
	PROPID_ARRAY propids;
	PROPID_ARRAY propids1;
	PROPNAME_ARRAY propnames;
	
	propids.count = 0;
	propids.ppropid = static_cast<uint16_t *>(alloc(sizeof(uint16_t) * phash.size()));
	if (propids.ppropid == nullptr)
		return FALSE;
	propnames.count = 0;
	propnames.ppropname = static_cast<PROPERTY_NAME *>(alloc(sizeof(PROPERTY_NAME) * phash.size()));
	if (propnames.ppropname == nullptr)
		return FALSE;
	for (const auto &pair : phash) {
		propids.ppropid[propids.count++] = pair.first;
		propnames.ppropname[propnames.count++] = pair.second;
	}
	if (!get_propids(&propnames, &propids1))
		return FALSE;
	propididmap_t phash1;
	for (size_t i = 0; i < propids.count; ++i) try {
		phash1.emplace(propids.ppropid[i], propids1.ppropid[i]);
	} catch (const std::bad_alloc &) {
	}
	oxcical_replace_propid(&pmsg->proplist, phash1);
	if (pmsg->children.prcpts != nullptr)
		for (size_t i = 0; i < pmsg->children.prcpts->count; ++i)
			oxcical_replace_propid(pmsg->children.prcpts->pparray[i], phash1);
	if (pmsg->children.pattachments != nullptr)
		for (size_t i = 0; i < pmsg->children.pattachments->count; ++i)
			oxcical_replace_propid(
				&pmsg->children.pattachments->pplist[i]->proplist, phash1);
	return TRUE;
}

static BOOL oxcical_parse_exceptional_attachment(ATTACHMENT_CONTENT *pattachment,
    const ical_component &, ICAL_TIME start_itime,
    ICAL_TIME end_itime, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	time_t tmp_time;
	uint8_t tmp_byte;
	uint32_t tmp_int32;
	uint64_t tmp_int64;
	
	tmp_int32 = ATTACH_EMBEDDED_MSG;
	if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) != 0)
		return FALSE;
	if (pattachment->proplist.set(PR_RENDERING_POSITION, &indet_rendering_pos) != 0)
		return FALSE;
	auto newval = pattachment->pembedded->proplist.getval(PR_SUBJECT);
	if (newval != nullptr &&
	    pattachment->proplist.set(PR_DISPLAY_NAME, newval) != 0)
		return FALSE;
	if (!ical_itime_to_utc(nullptr, start_itime, &tmp_time))
		return FALSE;
	tmp_int64 = rop_util_unix_to_nttime(tmp_time);
	if (pattachment->proplist.set(PR_EXCEPTION_STARTTIME, &tmp_int64) != 0)
		return FALSE;
	if (!ical_itime_to_utc(nullptr, end_itime, &tmp_time))
		return FALSE;
	tmp_int64 = rop_util_unix_to_nttime(tmp_time);
	if (pattachment->proplist.set(PR_EXCEPTION_ENDTIME, &tmp_int64) != 0)
		return FALSE;
	tmp_bin.cb = 0;
	tmp_bin.pb = NULL;
	if (pattachment->proplist.set(PR_ATTACH_ENCODING, &tmp_bin) != 0)
		return FALSE;
	tmp_int32 = afException;
	if (pattachment->proplist.set(PR_ATTACHMENT_FLAGS, &tmp_int32) != 0)
		return FALSE;
	tmp_int32 = 0x00000000;
	if (pattachment->proplist.set(PR_ATTACHMENT_LINKID, &tmp_int32) != 0 ||
	    pattachment->proplist.set(PR_ATTACH_FLAGS, &tmp_int32) != 0)
		return FALSE;
	tmp_byte = 1;
	if (pattachment->proplist.set(PR_ATTACHMENT_HIDDEN, &tmp_byte) != 0)
		return FALSE;
	tmp_byte = 0;
	if (pattachment->proplist.set(PR_ATTACHMENT_CONTACTPHOTO, &tmp_byte) != 0)
		return FALSE;
	return TRUE;
}

static BOOL oxcical_parse_atx_value(const ical_line &piline,
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
		return TRUE;
	if (NULL == pmsg->children.pattachments) {
		pattachments = attachment_list_init();
		if (pattachments == nullptr)
			return FALSE;
		message_content_set_attachments_internal(
			pmsg, pattachments);
	} else {
		pattachments = pmsg->children.pattachments;
	}
	pattachment = attachment_content_init();
	if (pattachment == nullptr)
		return FALSE;
	if (!attachment_list_append_internal(pattachments, pattachment)) {
		attachment_content_free(pattachment);
		return FALSE;
	}
	tmp_bin.cb = gx_snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff),
		"[InternetShortcut]\r\nURL=%s", pvalue);
	tmp_bin.pc = tmp_buff;
	if (pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin) != 0)
		return FALSE;
	tmp_bin.cb = 0;
	tmp_bin.pb = NULL;
	if (pattachment->proplist.set(PR_ATTACH_ENCODING, &tmp_bin) != 0)
		return FALSE;
	if (pattachment->proplist.set(PR_ATTACH_EXTENSION, ".URL") != 0)
		return FALSE;
	auto pvalue1 = strrchr(pvalue, '/');
	if (pvalue1 == nullptr)
		pvalue1 = pvalue;
	snprintf(tmp_buff, 256, "%s.url", pvalue1);
	if (pattachment->proplist.set(PR_ATTACH_LONG_FILENAME, tmp_buff) != 0 ||
	    pattachment->proplist.set(PR_DISPLAY_NAME, tmp_buff) != 0)
		return FALSE;
	tmp_int32 = ATTACH_BY_VALUE;
	if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) != 0)
		return FALSE;
	pvalue1 = piline.get_first_paramval("FMTYPE");
	if (pvalue1 != nullptr &&
	    pattachment->proplist.set(PR_ATTACH_MIME_TAG, pvalue1) != 0)
		return FALSE;
	tmp_int32 = 0;
	if (pattachment->proplist.set(PR_ATTACH_FLAGS, &tmp_int32) != 0)
		return FALSE;
	tmp_int32 = 0;
	if (pattachment->proplist.set(PR_ATTACHMENT_LINKID, &tmp_int32) != 0)
		return FALSE;
	tmp_byte = 0;
	if (pattachment->proplist.set(PR_ATTACHMENT_CONTACTPHOTO, &tmp_byte) != 0)
		return FALSE;
	tmp_int64 = 0x0CB34557A3DD4000;
	if (pattachment->proplist.set(PR_EXCEPTION_STARTTIME, &tmp_int64) != 0 ||
	    pattachment->proplist.set(PR_EXCEPTION_ENDTIME, &tmp_int64) != 0)
		return FALSE;
	if (pattachment->proplist.set(PR_RENDERING_POSITION, &indet_rendering_pos) != 0)
		return FALSE;
	return TRUE;
}

static BOOL oxcical_parse_atx_binary(const ical_line &piline,
    int count, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	size_t decode_len;
	uint8_t tmp_byte;
	uint32_t tmp_int32;
	uint64_t tmp_int64;
	char tmp_buff[1024];
	ATTACHMENT_LIST *pattachments;
	ATTACHMENT_CONTENT *pattachment;

	auto pvalue = piline.get_first_paramval("ENCODING");
	if (pvalue == nullptr || strcasecmp(pvalue, "BASE64") != 0)
		return FALSE;
	if (NULL == pmsg->children.pattachments) {
		pattachments = attachment_list_init();
		if (pattachments == nullptr)
			return FALSE;
		message_content_set_attachments_internal(
			pmsg, pattachments);
	} else {
		pattachments = pmsg->children.pattachments;
	}
	pattachment = attachment_content_init();
	if (pattachment == nullptr)
		return FALSE;
	if (!attachment_list_append_internal(pattachments, pattachment)) {
		attachment_content_free(pattachment);
		return FALSE;
	}
	pvalue = piline.get_first_subvalue();
	if (NULL != pvalue) {
		tmp_int32 = strlen(pvalue);
		tmp_bin.pv = malloc(tmp_int32);
		if (tmp_bin.pv == nullptr)
			return FALSE;
		if (decode64(pvalue, tmp_int32, tmp_bin.pv, tmp_int32, &decode_len) != 0) {
			free(tmp_bin.pb);
			return FALSE;
		}
		tmp_bin.cb = decode_len;
	} else {
		tmp_bin.cb = 0;
		tmp_bin.pb = NULL;
	}
	if (pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin) != 0)
		return FALSE;
	if (tmp_bin.pb != nullptr)
		free(tmp_bin.pb);
	tmp_bin.cb = 0;
	tmp_bin.pb = NULL;
	if (pattachment->proplist.set(PR_ATTACH_ENCODING, &tmp_bin) != 0)
		return FALSE;
	pvalue = piline.get_first_paramval("X-FILENAME");
	if (pvalue == nullptr)
		pvalue = piline.get_first_paramval("FILENAME");
	if (NULL == pvalue) {
		snprintf(tmp_buff, arsizeof(tmp_buff), "calendar_attachment%d.dat", count);
		pvalue = tmp_buff;
	}
	auto pvalue1 = strrchr(pvalue, '.');
	if (pvalue1 == nullptr)
		pvalue1 = ".dat";
	if (pattachment->proplist.set(PR_ATTACH_EXTENSION, pvalue1) != 0 ||
	    pattachment->proplist.set(PR_ATTACH_LONG_FILENAME, pvalue) != 0 ||
	    pattachment->proplist.set(PR_DISPLAY_NAME, pvalue) != 0)
		return FALSE;
	tmp_int32 = ATTACH_BY_VALUE;
	if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) != 0)
		return FALSE;
	pvalue1 = piline.get_first_paramval("FMTYPE");
	if (pvalue1 != nullptr &&
	    pattachment->proplist.set(PR_ATTACH_MIME_TAG, pvalue1) != 0)
		return FALSE;
	tmp_int32 = 0;
	if (pattachment->proplist.set(PR_ATTACH_FLAGS, &tmp_int32) != 0 ||
	    pattachment->proplist.set(PR_ATTACHMENT_LINKID, &tmp_int32) != 0)
		return FALSE;
	tmp_byte = 0;
	if (pattachment->proplist.set(PR_ATTACHMENT_CONTACTPHOTO, &tmp_byte) != 0)
		return FALSE;
	tmp_int64 = 0x0CB34557A3DD4000;
	if (pattachment->proplist.set(PR_EXCEPTION_STARTTIME, &tmp_int64) != 0 ||
	    pattachment->proplist.set(PR_EXCEPTION_ENDTIME, &tmp_int64) != 0)
		return FALSE;
	if (pattachment->proplist.set(PR_RENDERING_POSITION, &indet_rendering_pos) != 0)
		return FALSE;
	return TRUE;
}

static BOOL oxcical_parse_attachment(const ical_line &piline,
    int count, MESSAGE_CONTENT *pmsg)
{
	auto v = piline.get_first_paramval("VALUE");
	if (v == nullptr)
		return oxcical_parse_atx_value(piline, count, pmsg);
	else if (strcasecmp(v, "BINARY") == 0)
		return oxcical_parse_atx_binary(piline, count, pmsg);
	return TRUE;
}

static BOOL oxcical_parse_valarm(uint32_t reminder_delta, time_t start_time,
    namemap &phash, uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	uint8_t tmp_byte;
	uint64_t tmp_int64;
	PROPERTY_NAME propname = {MNID_ID, PSETID_COMMON, PidLidReminderDelta};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	if (pmsg->proplist.set(PROP_TAG(PT_LONG, *plast_propid), &reminder_delta) != 0)
		return FALSE;
	(*plast_propid) ++;
	propname.guid = PSETID_COMMON;
	propname.kind = MNID_ID;
	propname.lid = PidLidReminderTime;
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	tmp_int64 = rop_util_unix_to_nttime(start_time);
	if (pmsg->proplist.set(PROP_TAG(PT_SYSTIME, *plast_propid), &tmp_int64) != 0)
		return FALSE;
	(*plast_propid) ++;
	propname = {MNID_ID, PSETID_COMMON, PidLidReminderSignalTime};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	tmp_int64 = rop_util_unix_to_nttime(
		start_time - reminder_delta*60);
	if (pmsg->proplist.set(PROP_TAG(PT_SYSTIME, *plast_propid), &tmp_int64) != 0)
		return FALSE;
	(*plast_propid) ++;
	propname = {MNID_ID, PSETID_COMMON, PidLidReminderSet};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	tmp_byte = 1;
	if (pmsg->proplist.set(PROP_TAG(PT_BOOLEAN, *plast_propid), &tmp_byte) != 0)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static const ical_component *oxcical_main_event(const event_list_t &evlist)
{
	if (evlist.size() == 1)
		return evlist.front().get();
	std::shared_ptr<ical_component> main_event;
	for (const auto &event : evlist) {
		auto line = event->get_line("RECURRENCE-ID");
		if (line != nullptr) {
			if (event->get_line("X-MICROSOFT-RRULE") != nullptr ||
			    event->get_line("RRULE") != nullptr)
				return nullptr;
			continue;
		}
		if (main_event != nullptr)
			return nullptr;
		main_event = event;
		if (main_event->get_line("X-MICROSOFT-RRULE") == nullptr &&
		    main_event->get_line("RRULE") == nullptr)
			return nullptr;
	}
	return main_event.get();
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

static BOOL oxcical_import_internal(const char *str_zone, const char *method,
    BOOL b_proposal, uint16_t calendartype, const ical &pical,
    const event_list_t &pevent_list, EXT_BUFFER_ALLOC alloc,
    GET_PROPIDS get_propids, USERNAME_TO_ENTRYID username_to_entryid,
    MESSAGE_CONTENT *pmsg, ICAL_TIME *pstart_itime, ICAL_TIME *pend_itime,
    EXCEPTIONINFO *pexception, EXTENDEDEXCEPTION *pext_exception)
{
	auto pmain_event = oxcical_main_event(pevent_list);
	if (pmain_event == nullptr)
		return FALSE;
	
	if (NULL != pexception && NULL != pext_exception) {
		memset(pexception, 0, sizeof(EXCEPTIONINFO));
		memset(pext_exception, 0, sizeof(EXTENDEDEXCEPTION));
		pext_exception->changehighlight.size = sizeof(uint32_t);
	}
	if (!oxcical_parse_recipients(*pmain_event, username_to_entryid, pmsg))
		return FALSE;
	uint16_t last_propid = 0x8000;
	namemap phash;
	if (b_proposal && !oxcical_parse_proposal(phash, &last_propid, pmsg))
		return FALSE;
	if (!oxcical_parse_categories(*pmain_event, phash, &last_propid, pmsg) ||
	    !oxcical_parse_class(*pmain_event, pmsg) ||
	    !oxcical_parse_body(*pmain_event, method, pmsg) ||
	    !oxcical_parse_html(*pmain_event, pmsg))
		return FALSE;
	BOOL b_allday = oxcical_parse_allday(*pmain_event) ? TRUE : false;
	if (!oxcical_parse_dtstamp(*pmain_event, method,
	    phash, &last_propid, pmsg))
		return FALSE;
	
	auto piline = pmain_event->get_line("DTSTART");
	if (NULL == piline) {
		printf("GW-2741: oxcical_import_internal: no DTSTART\n");
		return FALSE;
	}
	auto pvalue1 = piline->get_first_paramval("VALUE");
	auto ptzid = piline->get_first_paramval("TZID");
	const ical_component *ptz_component = nullptr;
	if (ptzid != nullptr) {
		ptz_component = oxcical_find_vtimezone(pical, ptzid);
		if (ptz_component == nullptr) {
			fprintf(stderr, "D-2070: %s: timezone \"%s\" not found\n", __func__, znul(ptzid));
			return FALSE;
		}
		if (!oxcical_parse_tzdisplay(TRUE, *ptz_component, phash,
		    &last_propid, pmsg))
			return FALSE;
	}

	bool b_utc, b_utc_start, b_utc_end;
	time_t start_time = 0, end_time = 0;
	ICAL_TIME start_itime, end_itime;
	if (!oxcical_parse_dtvalue(ptz_component,
	    *piline, &b_utc_start, &start_itime, &start_time))
		return FALSE;
	if (!oxcical_parse_start_end(TRUE, b_proposal,
	    *pmain_event, start_time, phash, &last_propid, pmsg))
		return FALSE;
	if (pstart_itime != nullptr)
		*pstart_itime = start_itime;

	piline = pmain_event->get_line("DTEND");
	if (NULL != piline) {
		auto pvalue = piline->get_first_paramval("TZID");
		bool parse_dtv = (pvalue == nullptr && ptzid == nullptr) ||
		                 (pvalue != nullptr && ptzid != nullptr &&
		                 strcasecmp(pvalue, ptzid) == 0);
		if (!parse_dtv)
			return FALSE;
		if (!oxcical_parse_dtvalue(ptz_component,
		    *piline, &b_utc_end, &end_itime, &end_time))
			return FALSE;
		if (end_time < start_time) {
			fprintf(stderr, "GW-2795: ical not imported due to end_time < start_time\n");
			return FALSE;
		}
	} else {
		piline = pmain_event->get_line("DURATION");
		if (NULL == piline) {
			end_itime = start_itime;
			if (NULL != pvalue1 && 0 == strcasecmp(pvalue1, "DATE")) {
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
				return FALSE;
			b_utc_end = b_utc_start;
			end_itime = start_itime;
			end_time = start_time + duration;
			end_itime.add_second(duration);
		}
	}
	
	if (pend_itime != nullptr)
		*pend_itime = end_itime;
	if (ptz_component != nullptr && !oxcical_parse_tzdisplay(false,
	    *ptz_component, phash, &last_propid, pmsg))
		return FALSE;
	if (!oxcical_parse_start_end(FALSE, b_proposal,
	    *pmain_event, end_time, phash, &last_propid, pmsg))
		return FALSE;
	uint32_t duration_min = (end_time - start_time) / 60;
	if (!oxcical_parse_duration(duration_min, phash, &last_propid, pmsg))
		return FALSE;
	
	if (!b_allday && !b_utc_start && !b_utc_end && start_itime.hour == 0 &&
	    start_itime.minute == 0 && start_itime.second == 0 &&
	    end_itime.hour == 0 && end_itime.minute == 0 &&
	    end_itime.second == 0 && end_itime.delta_day(start_itime) == 1)
		b_allday = TRUE;
	if (b_allday && !oxcical_parse_subtype(phash, &last_propid, pmsg, pexception))
		return FALSE;
	
	ICAL_TIME itime{};
	piline = pmain_event->get_line("RECURRENCE-ID");
	if (NULL != piline) {
		if (pexception != nullptr && pext_exception != nullptr &&
		    !oxcical_parse_recurrence_id(ptz_component, *piline,
		    phash, &last_propid, pmsg))
			return FALSE;
		auto pvalue = piline->get_first_paramval("TZID");
		if (pvalue != nullptr && ptzid != nullptr &&
		    strcasecmp(pvalue, ptzid) != 0)
			return FALSE;
		if (NULL != pvalue) { 
			if (!oxcical_parse_dtvalue(ptz_component,
			    *piline, &b_utc, &itime, nullptr))
				return FALSE;
		} else {
			if (!oxcical_parse_dtvalue(nullptr,
			    *piline, &b_utc, &itime, nullptr))
				return FALSE;
			if (!b_utc && (itime.hour != 0 || itime.minute != 0 ||
			    itime.second != 0 || itime.leap_second != 0))
				return FALSE;
		}
	}
	
	if (!oxcical_parse_uid(*pmain_event, itime, alloc,
	    phash, &last_propid, pmsg) ||
	    !oxcical_parse_location(*pmain_event, phash, &last_propid, alloc,
	    pmsg, pexception, pext_exception) ||
	    !oxcical_parse_organizer(*pmain_event, username_to_entryid, pmsg) ||
	    !oxcical_parse_importance(*pmain_event, pmsg))
		return FALSE;
	if (!pmsg->proplist.has(PR_IMPORTANCE)) {
		int32_t tmp_int32 = IMPORTANCE_NORMAL;
		if (pmsg->proplist.set(PR_IMPORTANCE, &tmp_int32) != 0)
			return FALSE;
	}
	if (!oxcical_parse_sequence(*pmain_event, phash, &last_propid, pmsg))
		return FALSE;
	
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
		return false;
	if (!oxcical_set_busystatus(intent_status, PidLidIntendedBusyStatus, phash,
	    &last_propid, pmsg, nullptr))
		return false;

	if (!oxcical_parse_ownerapptid(*pmain_event, pmsg) ||
	    !oxcical_parse_disallow_counter(*pmain_event, phash,
	    &last_propid, pmsg) ||
	    !oxcical_parse_summary(*pmain_event, pmsg, alloc,
	    pexception, pext_exception))
		return FALSE;
	
	piline = pmain_event->get_line("RRULE");
	if (piline == nullptr)
		piline = pmain_event->get_line("X-MICROSOFT-RRULE");
	if (NULL != piline) {
		if (ptz_component != nullptr &&
		    !oxcical_parse_recurring_timezone(*ptz_component,
		    phash, &last_propid, pmsg))
			return FALSE;

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
			return FALSE;
		piline = pmain_event->get_line("EXDATE");
		if (piline == nullptr)
			piline = pmain_event->get_line("X-MICROSOFT-EXDATE");
		if (piline != nullptr && !oxcical_parse_dates(ptz_component,
		    *piline, &apr.recur_pat.deletedinstancecount, deleted_dates))
			return false;
		piline = pmain_event->get_line("RDATE");
		if (NULL != piline) {
			if (!oxcical_parse_dates(ptz_component, *piline,
			    &apr.recur_pat.modifiedinstancecount, modified_dates))
				return FALSE;
			if (apr.recur_pat.modifiedinstancecount < apr.recur_pat.deletedinstancecount)
				return FALSE;
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
				return FALSE;
			message_content_set_attachments_internal(pmsg, pattachments);
		}
		for (auto event : pevent_list) {
			if (event.get() == pmain_event)
				continue;
			auto pattachment = attachment_content_init();
			if (pattachment == nullptr)
				return FALSE;
			if (!attachment_list_append_internal(pattachments, pattachment)) {
				attachment_content_free(pattachment);
				return FALSE;
			}
			auto pembedded = message_content_init();
			if (pembedded == nullptr)
				return FALSE;
			attachment_content_set_embedded_internal(pattachment, pembedded);
			if (pembedded->proplist.set(PR_MESSAGE_CLASS, "IPM.OLE.CLASS.{00061055-0000-0000-C000-000000000046}") != 0)
				return FALSE;
			
			event_list_t tmp_list;
			try {
				tmp_list.push_back(event);
			} catch (...) {
				return false;
			}
			if (!oxcical_import_internal(str_zone, method, false,
			    calendartype, pical, tmp_list, alloc, get_propids,
			    username_to_entryid, pembedded, &start_itime,
			    &end_itime, exceptions + apr.exceptioncount,
			    ext_exceptions + apr.exceptioncount))
				return FALSE;
			if (!oxcical_parse_exceptional_attachment(pattachment,
			    *event, start_itime, end_itime, pmsg))
				return FALSE;
			
			piline = event->get_line("RECURRENCE-ID");
			time_t tmp_time;
			if (!oxcical_parse_dtvalue(ptz_component,
			    *piline, &b_utc, &itime, &tmp_time))
				return FALSE;
			auto minutes = rop_util_unix_to_nttime(tmp_time) / 600000000U;
			size_t i;
			for (i = 0; i < apr.recur_pat.deletedinstancecount; ++i)
				if (deleted_dates[i] == minutes)
					break;
			if (i < apr.recur_pat.deletedinstancecount)
				continue;
			deleted_dates[apr.recur_pat.deletedinstancecount++] = minutes;
			if (apr.recur_pat.deletedinstancecount >= 1024)
				return FALSE;
			exceptions[apr.exceptioncount].originalstartdate = minutes;
			ext_exceptions[apr.exceptioncount].originalstartdate = minutes;
			ical_itime_to_utc(NULL, start_itime, &tmp_time);
			minutes = rop_util_unix_to_nttime(tmp_time)/600000000;
			modified_dates[apr.recur_pat.modifiedinstancecount++] = minutes;
			exceptions[apr.exceptioncount].startdatetime = minutes;
			ext_exceptions[apr.exceptioncount].startdatetime = minutes;
			ical_itime_to_utc(NULL, end_itime, &tmp_time);
			minutes = rop_util_unix_to_nttime(tmp_time)/600000000;
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
			return FALSE;
	}
	
	size_t tmp_count = 0;
	for (const auto &line : pmain_event->line_list) {
		if (strcasecmp(line.m_name.c_str(), "ATTACH") != 0)
			continue;
		tmp_count ++;
		if (!oxcical_parse_attachment(line, tmp_count, pmsg))
			return FALSE;
	}
	
	BOOL b_alarm = FALSE;
	uint32_t alarmdelta = 0;
	if (pmain_event->component_list.size() > 0) {
		auto palarm_component = pmain_event->component_list.front();
		if (strcasecmp(palarm_component->m_name.c_str(), "VALARM") == 0) {
			b_alarm = TRUE;
			piline = palarm_component->get_line("TRIGGER");
			const char *pvalue = nullptr;
			if (piline == nullptr ||
			    (pvalue = piline->get_first_subvalue()) == nullptr) {
				alarmdelta = dfl_alarm_offset(b_allday);
			} else {
				pvalue1 = piline->get_first_paramval("RELATED");
				if (NULL == pvalue1) {
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
				return FALSE;
		}
	}
	
	if (NULL != pexception) {
		if (!b_alarm) {
			pexception->overrideflags |= ARO_REMINDER;
			pexception->reminderset = 0;
		} else {
			pexception->overrideflags |= ARO_REMINDERDELTA;
			pexception->reminderdelta = alarmdelta;
		}
	}
	return oxcical_fetch_propname(pmsg, phash, alloc, get_propids);
}

static BOOL oxcical_import_events(const char *str_zone, uint16_t calendartype,
    const ical &pical, const uidxevent_list_t &uid_list, EXT_BUFFER_ALLOC alloc,
    GET_PROPIDS get_propids, USERNAME_TO_ENTRYID username_to_entryid,
    std::vector<message_ptr> &msgvec)
{
	for (const auto &listentry : uid_list) {
		auto &event_list = listentry.second;
		message_ptr msg(message_content_init());
		if (msg == nullptr)
			return FALSE;
		msgvec.push_back(std::move(msg));
		auto pembedded = msgvec.back().get();
		if (pembedded->proplist.set(PR_MESSAGE_CLASS, "IPM.Appointment") != 0)
			return FALSE;
		if (!oxcical_import_internal(str_zone, "PUBLISH", false,
		    calendartype, pical, event_list, alloc, get_propids,
		    username_to_entryid, pembedded, nullptr, nullptr, nullptr,
		    nullptr))
			return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_classify_calendar(const ical &pical, uidxevent_list_t &ul) try
{
	for (const auto &pcomponent : pical.component_list) {
		if (strcasecmp(pcomponent->m_name.c_str(), "VEVENT") != 0)
			continue;
		auto piline = pcomponent->get_line("UID");
		auto puid = piline != nullptr ? piline->get_first_subvalue() : "";
		ul[puid].push_back(pcomponent);
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-2053: ENOMEM\n");
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
	return NULL;
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

ec_error_t oxcical_import_multi(const char *str_zone, const ical &pical,
    EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
    USERNAME_TO_ENTRYID username_to_entryid, std::vector<message_ptr> &finalvec)
{
	BOOL b_proposal;
	const char *pvalue = nullptr, *pvalue1 = nullptr;
	
	b_proposal = FALSE;
	auto piline = pical.get_line("X-MICROSOFT-CALSCALE");
	uint16_t calendartype = oxcical_get_calendartype(piline);
	auto mclass = "IPM.Appointment";
	std::vector<message_ptr> msgvec;
	uidxevent_list_t uid_list;
	if (!oxcical_classify_calendar(pical, uid_list) ||
	    uid_list.size() == 0)
		return ecNotFound;
	piline = pical.get_line("METHOD");
	if (NULL != piline) {
		pvalue = piline->get_first_subvalue();
		if (NULL != pvalue) {
			if (0 == strcasecmp(pvalue, "PUBLISH")) {
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
			} else if (0 == strcasecmp(pvalue, "REQUEST")) {
				if (uid_list.size() != 1)
					return ecNotFound;
				mclass = "IPM.Schedule.Meeting.Request";
			} else if (0 == strcasecmp(pvalue, "REPLY")) {
				if (uid_list.size() != 1)
					return ecNotFound;
				pvalue1 = oxcical_get_partstat(uid_list);
				if (NULL != pvalue1) {
					if (strcasecmp(pvalue1, "ACCEPTED") == 0)
						mclass = "IPM.Schedule.Meeting.Resp.Pos";
					else if (strcasecmp(pvalue1, "TENTATIVE") == 0)
						mclass = "IPM.Schedule.Meeting.Resp.Tent";
					else if (strcasecmp(pvalue1, "DECLINED") == 0)
						mclass = "IPM.Schedule.Meeting.Resp.Neg";
				}
			} else if (0 == strcasecmp(pvalue, "COUNTER")) {
				if (uid_list.size() != 1)
					return ecNotFound;
				pvalue1 = oxcical_get_partstat(uid_list);
				if (NULL != pvalue1 && 0 == strcasecmp(pvalue1, "TENTATIVE")) {
					mclass = "IPM.Schedule.Meeting.Resp.Tent";
					b_proposal = TRUE;
				}
			} else if (0 == strcasecmp(pvalue, "CANCEL")) {
				mclass = "IPM.Schedule.Meeting.Canceled";
			}
		}
	} else {
		if (!oxcical_import_events(str_zone, calendartype,
		    pical, uid_list, alloc, get_propids,
		    username_to_entryid, msgvec))
			return ecError;
		finalvec.insert(finalvec.end(), std::make_move_iterator(msgvec.begin()), std::make_move_iterator(msgvec.end()));
		return ecSuccess;
	}
	message_ptr msg(message_content_init());
	if (msg == nullptr)
		return ecMAPIOOM;
	msgvec.push_back(std::move(msg));
	auto pmsg = msgvec.back().get();
	if (pmsg->proplist.set(PR_MESSAGE_CLASS, mclass) != 0 ||
	    !oxcical_import_internal(str_zone, pvalue, b_proposal, calendartype,
	    pical, uid_list.begin()->second, alloc, get_propids,
	    username_to_entryid, pmsg, nullptr, nullptr, nullptr, nullptr))
		return ecError;
	finalvec.insert(finalvec.end(), std::make_move_iterator(msgvec.begin()), std::make_move_iterator(msgvec.end()));
	return ecSuccess;
}

message_ptr oxcical_import_single(const char *str_zone,
    const ical &pical, EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
    USERNAME_TO_ENTRYID username_to_entryid)
{
	std::vector<message_ptr> vec;
	if (oxcical_import_multi(str_zone, pical, alloc, get_propids,
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
	message_content_set_attachments_internal(cmsg.get(), atlist);
	for (auto &&emb : vec) {
		auto at = attachment_content_init();
		if (at == nullptr)
			return nullptr;
		if (!attachment_list_append_internal(atlist, at)) {
			attachment_content_free(at);
			return nullptr;
		}
		attachment_content_set_embedded_internal(at, emb.release());
	}
	return cmsg;
}

static int sprintf_dt(char *b, size_t z, const ICAL_TIME &t)
{
	return snprintf(b, z, fmt_date, t.year, t.month, t.day);
}

static int sprintf_dtlcl(char *b, size_t z, const ICAL_TIME &t)
{
	return snprintf(b, z, fmt_datetimelcl, t.year, t.month, t.day, t.hour,
	       t.minute, t.second);
}

static int sprintf_dtutc(char *b, size_t z, const ICAL_TIME &t)
{
	return snprintf(b, z, fmt_datetimeutc, t.year, t.month, t.day, t.hour,
	       t.minute, t.second);
}

static std::shared_ptr<ICAL_COMPONENT> oxcical_export_timezone(ical &pical,
	int year, const char *tzid, TIMEZONESTRUCT *ptzstruct)
{
	int day;
	int order;
	std::shared_ptr<ICAL_VALUE> pivalue;
	char tmp_buff[1024];
	
	auto pcomponent = ical_new_component("VTIMEZONE");
	if (pcomponent == nullptr)
		return NULL;
	pical.append_comp(pcomponent);
	auto piline = ical_new_simple_line("TZID", tzid);
	if (piline == nullptr)
		return NULL;
	if (pcomponent->append_line(piline) < 0)
		return nullptr;
	/* STANDARD component */
	auto pcomponent1 = ical_new_component("STANDARD");
	if (pcomponent1 == nullptr)
		return NULL;
	pcomponent->append_comp(pcomponent1);
	order = ptzstruct->standarddate.day;
	if (order == 5)
		order = -1;
	if (0 == ptzstruct->daylightdate.month) {
		strcpy(tmp_buff, "16010101T000000");
	} else if (ptzstruct->standarddate.year == 0) {
		day = ical_get_dayofmonth(year,
			ptzstruct->standarddate.month, order,
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
		return NULL;
	}
	piline = ical_new_simple_line("DTSTART", tmp_buff);
	if (piline == nullptr)
		return NULL;
	if (pcomponent1->append_line(piline) < 0)
		return nullptr;
	if (0 != ptzstruct->daylightdate.month) {
		if (0 == ptzstruct->standarddate.year) {
			piline = ical_new_line("RRULE");
			if (piline == nullptr)
				return NULL;
			if (pcomponent1->append_line(piline) < 0)
				return nullptr;
			piline->append_value("FREQ", "YEARLY");
			auto dow = weekday_to_str(ptzstruct->standarddate.dayofweek);
			if (dow == nullptr)
				return nullptr;
			snprintf(tmp_buff, std::size(tmp_buff), "%d%s", order, dow);
			piline->append_value("BYDAY", tmp_buff);
			snprintf(tmp_buff, arsizeof(tmp_buff), "%d", (int)ptzstruct->standarddate.month);
			piline->append_value("BYMONTH", tmp_buff);
		} else if (1 == ptzstruct->standarddate.year) {
			piline = ical_new_line("RRULE");
			if (piline == nullptr)
				return NULL;
			if (pcomponent1->append_line(piline) < 0)
				return nullptr;
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
	piline = ical_new_simple_line("TZOFFSETFROM", tmp_buff);
	if (piline == nullptr)
		return nullptr;
	if (pcomponent1->append_line(piline) < 0)
		return nullptr;
	utc_offset = -(ptzstruct->bias + ptzstruct->standardbias);
	tmp_buff[0] = utc_offset >= 0 ? '+' : '-';
	utc_offset = abs(utc_offset);
	sprintf(tmp_buff + 1, "%02d%02d", utc_offset/60, utc_offset%60);
	piline = ical_new_simple_line("TZOFFSETTO", tmp_buff);
	if (pcomponent1->append_line(piline) < 0)
		return nullptr;
	if (ptzstruct->daylightdate.month == 0)
		return pcomponent;
	/* DAYLIGHT component */
	pcomponent1 = ical_new_component("DAYLIGHT");
	if (pcomponent1 == nullptr)
		return NULL;
	pcomponent->append_comp(pcomponent1);
	order = ptzstruct->daylightdate.day;
	if (order == 5)
		order = -1;
	if (0 == ptzstruct->daylightdate.year) {
		day = ical_get_dayofmonth(year,
			ptzstruct->daylightdate.month, order,
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
		return NULL;
	}
	piline = ical_new_simple_line("DTSTART", tmp_buff);
	if (piline == nullptr)
		return NULL;
	if (pcomponent1->append_line(piline) < 0)
		return nullptr;
	if (0 == ptzstruct->daylightdate.year) {
		piline = ical_new_line("RRULE");
		if (piline == nullptr)
			return NULL;
		if (pcomponent1->append_line(piline) < 0)
			return nullptr;
		piline->append_value("FREQ", "YEARLY");
		auto dow = weekday_to_str(ptzstruct->daylightdate.dayofweek);
		if (dow == nullptr)
			return nullptr;
		snprintf(tmp_buff, std::size(tmp_buff), "%d%s", order, dow);
		piline->append_value("BYDAY", tmp_buff);
		snprintf(tmp_buff, arsizeof(tmp_buff), "%d", (int)ptzstruct->daylightdate.month);
		piline->append_value("BYMONTH", tmp_buff);
	} else if (1 == ptzstruct->daylightdate.year) {
		piline = ical_new_line("RRULE");
		if (piline == nullptr)
			return NULL;
		if (pcomponent1->append_line(piline) < 0)
			return nullptr;
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
	piline = ical_new_simple_line("TZOFFSETFROM", tmp_buff);
	if (piline == nullptr)
		return nullptr;
	if (pcomponent1->append_line(piline) < 0)
		return nullptr;
	utc_offset = -(ptzstruct->bias + ptzstruct->daylightbias);
	tmp_buff[0] = utc_offset >= 0 ? '+' : '-';
	utc_offset = abs(utc_offset);
	sprintf(tmp_buff + 1, "%02d%02d", utc_offset/60, utc_offset%60);
	piline = ical_new_simple_line("TZOFFSETTO", tmp_buff);
	if (piline == nullptr)
		return nullptr;
	if (pcomponent1->append_line(piline) < 0)
		return nullptr;
	return pcomponent;
}

static BOOL oxcical_get_smtp_address(TPROPVAL_ARRAY *prcpt,
	ENTRYID_TO_USERNAME entryid_to_username,
	ESSDN_TO_USERNAME essdn_to_username,
    EXT_BUFFER_ALLOC alloc, char *username, size_t ulen)
{
	auto smtpaddr = prcpt->get<const char>(PR_SMTP_ADDRESS);
	if (smtpaddr != nullptr) {
		gx_strlcpy(username, smtpaddr, ulen);
		return TRUE;
	}
	auto addrtype = prcpt->get<const char>(PR_ADDRTYPE);
	if (addrtype == nullptr) {
		auto entryid = prcpt->get<const BINARY>(PR_ENTRYID);
		if (entryid == nullptr)
			return FALSE;
		return entryid_to_username(entryid, alloc, username, ulen);
	}
	const char *emaddr = nullptr;
	if (strcasecmp(addrtype, "SMTP") == 0) {
		emaddr = prcpt->get<char>(PR_EMAIL_ADDRESS);
	} else if (strcasecmp(addrtype, "EX") == 0) {
		emaddr = prcpt->get<char>(PR_EMAIL_ADDRESS);
		if (emaddr != nullptr) {
			if (essdn_to_username(emaddr, username, ulen))
				return TRUE;
			emaddr = nullptr;
		}
	}
	if (emaddr == nullptr) {
		auto entryid = prcpt->get<const BINARY>(PR_ENTRYID);
		if (entryid == nullptr)
			return FALSE;
		return entryid_to_username(entryid, alloc, username, ulen);
	}
	gx_strlcpy(username, emaddr, ulen);
	return TRUE;
}

static bool is_meeting_response(const char *s)
{
	return strcasecmp(s, "IPM.Schedule.Meeting.Resp.Pos") == 0 ||
	       strcasecmp(s, "IPM.Schedule.Meeting.Resp.Neg") == 0 ||
	       strcasecmp(s, "IPM.Schedule.Meeting.Resp.Tent") == 0;
}

static BOOL oxcical_export_recipient_table(ical_component &pevent_component,
    ENTRYID_TO_USERNAME entryid_to_username, ESSDN_TO_USERNAME essdn_to_username,
    EXT_BUFFER_ALLOC alloc, const char *partstat,
    const MESSAGE_CONTENT *pmsg) try
{
	std::shared_ptr<ICAL_LINE> piline;
	char username[UADDR_SIZE];
	char tmp_value[334];
	std::shared_ptr<ICAL_PARAM> piparam;
	std::shared_ptr<ICAL_VALUE> pivalue;
	
	if (pmsg->children.prcpts == nullptr)
		return TRUE;
	auto str = pmsg->proplist.get<const char>(PR_MESSAGE_CLASS);
	if (str == nullptr)
		str = pmsg->proplist.get<char>(PR_MESSAGE_CLASS_A);
	if (str == nullptr)
		return FALSE;
	/* ignore ATTENDEE when METHOD is "PUBLIC" */
	if (strcasecmp(str, "IPM.Appointment") == 0)
		return TRUE;
	if (is_meeting_response(str)) {
		str = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
		if (str == nullptr)
			return FALSE;
		piline = ical_new_line("ATTENDEE");
		if (piline == nullptr)
			return FALSE;
		if (pevent_component.append_line(piline) < 0)
			return false;
		piline->append_param("PARTSTAT", partstat);
		snprintf(tmp_value, sizeof(tmp_value), "MAILTO:%s", str);
		piline->append_value(nullptr, tmp_value);
		return TRUE;
	}	
	auto flag = pmsg->proplist.get<const uint8_t>(PR_RESPONSE_REQUESTED);
	auto b_rsvp = flag != nullptr && *flag != 0;
	for (size_t i = 0; i < pmsg->children.prcpts->count; ++i) {
		auto rcptflags = pmsg->children.prcpts->pparray[i]->get<const uint32_t>(PR_RECIPIENT_FLAGS);
		if (rcptflags == nullptr)
			continue;
		if (*rcptflags & (recipExceptionalDeleted | recipOrganizer))
			continue;
		auto rcpttype = pmsg->children.prcpts->pparray[i]->get<const uint32_t>(PR_RECIPIENT_TYPE);
		if (rcpttype != nullptr && *rcpttype == MAPI_ORIG)
			continue;
		piline = ical_new_line("ATTENDEE");
		if (piline == nullptr)
			return FALSE;
		if (pevent_component.append_line(piline) < 0)
			return false;
		const char *role =
			rcpttype == nullptr ? "REQ-PARTICIPANT" :
			*rcpttype == MAPI_CC ? "OPT-PARTICIPANT" :
			*rcpttype == MAPI_BCC ? "NON-PARTICIPANT" :
			"REQ-PARTICIPANT";
		piline->append_param("ROLE", role);
		if (NULL != partstat) {
			piline->append_param("PARTSTAT", partstat);
		}
		if (b_rsvp) {
			piline->append_param("RSVP", "TRUE");
		}
		auto name = pmsg->children.prcpts->pparray[i]->get<const char>(PR_DISPLAY_NAME);
		if (name != nullptr) {
			piline->append_param("CN", name);
		}
		if (!oxcical_get_smtp_address(pmsg->children.prcpts->pparray[i],
		    entryid_to_username, essdn_to_username, alloc, username,
		    GX_ARRAY_SIZE(username)))
			return FALSE;
		snprintf(tmp_value, GX_ARRAY_SIZE(tmp_value), "MAILTO:%s", username);
		piline->append_value(nullptr, tmp_value);
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-2094: ENOMEM\n");
	return false;
}

static BOOL oxcical_export_rrule(const ical_component &ptz_component,
    ical_component &pcomponent, APPOINTMENT_RECUR_PAT *apr) try
{
	ICAL_TIME itime;
	time_t unix_time;
	uint64_t nt_time;
	const char *str_tag;
	char tmp_buff[1024];
	
	str_tag = NULL;
	switch (apr->recur_pat.calendartype) {
	case CAL_DEFAULT:
		switch (apr->recur_pat.patterntype) {
		case PATTERNTYPE_HJMONTH:
		case PATTERNTYPE_HJMONTHNTH:
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
		return FALSE;
	auto piline = ical_new_line(str_tag);
	if (piline == nullptr)
		return FALSE;
	if (pcomponent.append_line(piline) < 0)
		return false;
	switch (apr->recur_pat.patterntype) {
	case PATTERNTYPE_DAY:
		piline->append_value("FREQ", "DAILY");
		snprintf(tmp_buff, arsizeof(tmp_buff), "%u", apr->recur_pat.period / 1440);
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
			snprintf(tmp_buff, arsizeof(tmp_buff), "%u", apr->recur_pat.period / 12);
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
	if (ENDTYPE_AFTER_N_OCCURRENCES ==
		apr->recur_pat.endtype) {
		snprintf(tmp_buff, arsizeof(tmp_buff), "%u",
			apr->recur_pat.occurrencecount);
		piline->append_value("COUNT", tmp_buff);
	} else if (ENDTYPE_AFTER_DATE ==
		apr->recur_pat.endtype) {
		nt_time = apr->recur_pat.enddate
						+ apr->starttimeoffset;
		nt_time *= 600000000;
		unix_time = rop_util_nttime_to_unix(nt_time);
		ical_utc_to_datetime(NULL, unix_time, &itime);
		if (!ical_itime_to_utc(&ptz_component, itime, &unix_time))
			return FALSE;
		ical_utc_to_datetime(NULL, unix_time, &itime);
		sprintf_dtutc(tmp_buff, std::size(tmp_buff), itime);
		piline->append_value("UNTIL", tmp_buff);
	}
	if (PATTERNTYPE_WEEK == apr->recur_pat.patterntype) {
		auto wd = weekday_to_str(apr->recur_pat.firstdow);
		if (wd == nullptr)
			return FALSE;
		piline->append_value("WKST", wd);
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-2091: ENOMEM\n");
	return false;
}

static BOOL oxcical_check_exdate(APPOINTMENT_RECUR_PAT *apr)
{
	BOOL b_found;
	size_t count = 0;
	for (size_t i = 0; i < apr->recur_pat.deletedinstancecount; ++i) {
		b_found = FALSE;
		for (size_t j = 0; j < apr->exceptioncount; ++j) {
			if (apr->recur_pat.pdeletedinstancedates[i]
				== apr->pexceptioninfo[j].originalstartdate &&
				0 != apr->pexceptioninfo[j].overrideflags) {
				b_found = TRUE;
				break;
			}
		}
		if (!b_found)
			count ++;
	}
	return count != 0 ? TRUE : false;
}

static BOOL oxcical_export_exdate(const char *tzid, BOOL b_date,
    ical_component &pcomponent, APPOINTMENT_RECUR_PAT *apr) try
{
	BOOL b_found;
	ICAL_TIME itime;
	std::shared_ptr<ICAL_LINE> piline;
	std::shared_ptr<ICAL_PARAM> piparam;
	char tmp_buff[1024];
	
	if (apr->recur_pat.calendartype != CAL_DEFAULT ||
	    apr->recur_pat.patterntype == PATTERNTYPE_HJMONTH ||
	    apr->recur_pat.patterntype == PATTERNTYPE_HJMONTHNTH)
		piline = ical_new_line("X-MICROSOFT-EXDATE");
	else
		piline = ical_new_line("EXDATE");
	if (piline == nullptr)
		return FALSE;
	if (pcomponent.append_line(piline) < 0)
		return false;
	auto &pivalue = piline->append_value();
	if (b_date) {
		piline->append_param("VALUE", "DATE");
	} else if (tzid != nullptr) {
		piline->append_param("TZID", tzid);
	}
	for (size_t i = 0; i < apr->recur_pat.deletedinstancecount; ++i) {
		b_found = FALSE;
		for (size_t j = 0; j < apr->exceptioncount; ++j) {
			if (apr->recur_pat.pdeletedinstancedates[i]
				== apr->pexceptioninfo[j].originalstartdate &&
				0 != apr->pexceptioninfo[j].overrideflags) {
				b_found = TRUE;
				break;
			}
		}
		if (b_found)
			continue;
		auto tmp_int64 = (apr->recur_pat.pdeletedinstancedates[i] + apr->starttimeoffset) * 600000000ULL;
		ical_utc_to_datetime(nullptr, rop_util_nttime_to_unix(tmp_int64), &itime);
		if (b_date)
			sprintf_dt(tmp_buff, std::size(tmp_buff), itime);
		else if (tzid == nullptr)
			sprintf_dtutc(tmp_buff, std::size(tmp_buff), itime);
		else
			sprintf_dtlcl(tmp_buff, std::size(tmp_buff), itime);
		pivalue.append_subval(tmp_buff);
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-2095: ENOMEM\n");
	return false;
}

static BOOL oxcical_check_rdate(APPOINTMENT_RECUR_PAT *apr)
{
	size_t count = 0;
	BOOL b_found;
	
	for (size_t i = 0; i < apr->recur_pat.modifiedinstancecount; ++i) {
		b_found = FALSE;
		for (size_t j = 0; j < apr->exceptioncount; ++j) {
			if (apr->recur_pat.pmodifiedinstancedates[i]
				== apr->pexceptioninfo[j].startdatetime &&
				0 != apr->pexceptioninfo[j].overrideflags) {
				b_found = TRUE;
				break;
			}
		}
		if (!b_found)
			count ++;
	}
	return count != 0 ? TRUE : false;
}

static BOOL oxcical_export_rdate(const char *tzid, BOOL b_date,
     ical_component &pcomponent, APPOINTMENT_RECUR_PAT *apr) try
{
	BOOL b_found;
	ICAL_TIME itime;
	std::shared_ptr<ICAL_PARAM> piparam;
	char tmp_buff[1024];
	
	auto piline = ical_new_line("RDATE");
	if (piline == nullptr)
		return FALSE;
	if (pcomponent.append_line(piline) < 0)
		return false;
	auto &pivalue = piline->append_value();
	if (b_date) {
		piline->append_param("VALUE", "DATE");
	} else if (tzid != nullptr) {
		piline->append_param("TZID", tzid);
	}
	for (size_t i = 0; i < apr->recur_pat.deletedinstancecount; ++i) {
		b_found = FALSE;
		for (size_t j = 0; j < apr->exceptioncount; ++j) {
			if (apr->recur_pat.pmodifiedinstancedates[i]
				== apr->pexceptioninfo[j].startdatetime &&
				0 != apr->pexceptioninfo[j].overrideflags) {
				b_found = TRUE;
				break;
			}
		}
		if (b_found)
			continue;
		auto tmp_int64 = apr->recur_pat.pmodifiedinstancedates[i] * 600000000ULL;
		ical_utc_to_datetime(nullptr, rop_util_nttime_to_unix(tmp_int64), &itime);
		if (b_date)
			sprintf_dt(tmp_buff, std::size(tmp_buff), itime);
		else if (tzid == nullptr)
			sprintf_dtutc(tmp_buff, std::size(tmp_buff), itime);
		else
			sprintf_dtlcl(tmp_buff, std::size(tmp_buff), itime);
		pivalue.append_subval(tmp_buff);
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-2096: ENOMEM\n");
	return false;
}

static bool busystatus_to_line(ol_busy_status status, const char *key,
    ICAL_COMPONENT *com)
{
	auto it = std::lower_bound(std::cbegin(busy_status_names),
	          std::cend(busy_status_names), status,
	          [](const auto &p, ol_busy_status v) { return p.first < v; });
	if (it == std::cend(busy_status_names))
		return true;
	auto line = ical_new_simple_line(key, it->second);
	return line != nullptr && com->append_line(line) >= 0;
}

static BOOL oxcical_export_internal(const char *method, const char *tzid,
    std::shared_ptr<ICAL_COMPONENT> ptz_component, const MESSAGE_CONTENT *pmsg,
    ical &pical, ENTRYID_TO_USERNAME entryid_to_username,
    ESSDN_TO_USERNAME essdn_to_username,
    EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids) try
{
	int year;
	GUID guid;
	time_t cur_time;
	time_t end_time;
	ICAL_TIME itime;
	BOOL b_proposal;
	struct tm tmp_tm;
	EXT_PULL ext_pull;
	EXT_PUSH ext_push;
	time_t start_time;
	BOOL b_exceptional, b_recurrence = false;
	std::shared_ptr<ICAL_PARAM> piparam;
	char tmp_buff[1024];
	char tmp_buff1[2048];
	PROPID_ARRAY propids;
	const char *partstat;
	TIMEZONESTRUCT tz_struct;
	MESSAGE_CONTENT *pembedded;
	GLOBALOBJECTID globalobjectid;
	TIMEZONEDEFINITION tz_definition;
	APPOINTMENT_RECUR_PAT apprecurr;
	
	auto num = pmsg->proplist.get<const uint32_t>(PR_MESSAGE_LOCALE_ID);
	auto planguage = num != nullptr ? lcid_to_ltag(*num) : nullptr;
	auto str = pmsg->proplist.get<const char>(PR_MESSAGE_CLASS);
	if (str == nullptr)
		str = pmsg->proplist.get<char>(PR_MESSAGE_CLASS_A);
	if (str == nullptr)
		return FALSE;
	partstat = NULL;
	b_proposal = FALSE;
	if (NULL != method) {
		b_exceptional = TRUE;
	} else {
		b_exceptional = FALSE;
		if (strcasecmp(str, "IPM.Appointment") == 0) {
			method = "PUBLISH";
		} else if (strcasecmp(str, "IPM.Schedule.Meeting.Request") == 0) {
			method = "REQUEST";
			partstat = "NEEDS-ACTION";
		} else if (strcasecmp(str, "IPM.Schedule.Meeting.Resp.Pos") == 0) {
			method = "REPLY";
			partstat = "ACCEPTED";
		} else if (strcasecmp(str, "IPM.Schedule.Meeting.Resp.Tent") == 0) {
			partstat = "TENTATIVE";
			PROPERTY_NAME pn = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentCounterProposal};
			const PROPNAME_ARRAY pna = {1, &pn};
			if (!get_propids(&pna, &propids))
				return FALSE;
			auto flag = pmsg->proplist.get<const uint8_t>(PROP_TAG(PT_BOOLEAN, propids.ppropid[0]));
			if (flag != nullptr && *flag != 0) {
				b_proposal = TRUE;
				method = "COUNTER";
			} else {
				method = "REPLY";
			}
		} else if (strcasecmp(str, "IPM.Schedule.Meeting.Resp.Neg") == 0) {
			method = "REPLY";
			partstat = "DECLINED";
		} else if (strcasecmp(str, "IPM.Schedule.Meeting.Canceled") == 0) {
			method = "CANCEL";
			partstat = "NEEDS-ACTION";
		} else {
			return FALSE;
		}
	}
	PROPERTY_NAME propname = {MNID_ID, PSETID_APPOINTMENT, b_proposal ?
		PidLidAppointmentProposedStartWhole : PidLidAppointmentStartWhole};
	const PROPNAME_ARRAY propnames = {1, &propname};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	auto lnum = pmsg->proplist.get<const uint64_t>(PROP_TAG(PT_SYSTIME, propids.ppropid[0]));
	if (lnum == nullptr)
		return FALSE;
	start_time = rop_util_nttime_to_unix(*lnum);
	
	propname = {MNID_ID, PSETID_APPOINTMENT, b_proposal ?
	           PidLidAppointmentProposedEndWhole : PidLidAppointmentEndWhole};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	lnum = pmsg->proplist.get<uint64_t>(PROP_TAG(PT_SYSTIME, propids.ppropid[0]));
	if (lnum != nullptr) {
		end_time = rop_util_nttime_to_unix(*lnum);
	} else {
		propname = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentDuration};
		if (!get_propids(&propnames, &propids))
			return FALSE;
		end_time = start_time;
		num = pmsg->proplist.get<uint32_t>(PROP_TAG(PT_LONG, propids.ppropid[0]));
		if (num != nullptr)
			end_time += *num;
	}
	
	std::shared_ptr<ICAL_LINE> piline;
	BINARY *bin = nullptr;
	if (b_exceptional)
		goto EXPORT_VEVENT;
	
	piline = ical_new_simple_line("METHOD", method);
	if (piline == nullptr)
		return FALSE;
	if (pical.append_line(piline) < 0)
		return false;
	piline = ical_new_simple_line("PRODID", "gromox-oxcical");
	if (piline == nullptr)
		return FALSE;
	if (pical.append_line(piline) < 0)
		return false;
	
	piline = ical_new_simple_line("VERSION", "2.0");
	if (piline == nullptr)
		return FALSE;
	if (pical.append_line(piline) < 0)
		return false;
	
	propname = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentRecur};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	bin = pmsg->proplist.get<BINARY>(PROP_TAG(PT_BINARY, propids.ppropid[0]));
	if (bin == nullptr) {
		b_recurrence = FALSE;
	} else {
		ext_pull.init(bin->pb, bin->cb, alloc, EXT_FLAG_UTF16);
		if (ext_pull.g_apptrecpat(&apprecurr) != EXT_ERR_SUCCESS)
			return FALSE;
		b_recurrence = TRUE;
	}
	
	if (b_recurrence) {
		auto it = std::lower_bound(cal_scale_names, std::end(cal_scale_names),
		          apprecurr.recur_pat.calendartype,
		          [&](const auto &p, unsigned int v) { return p.first < v; });
		str = it != std::end(cal_scale_names) ? it->second : nullptr;
		if (PATTERNTYPE_HJMONTH ==
			apprecurr.recur_pat.patterntype ||
			PATTERNTYPE_HJMONTHNTH ==
			apprecurr.recur_pat.patterntype) {
			str = "Hijri";
		}
		if (str != nullptr) {
			piline = ical_new_simple_line(
				"X-MICROSOFT-CALSCALE", str);
			if (piline == nullptr)
				return FALSE;
			if (pical.append_line(piline) < 0)
				return false;
		}
	}
	
	make_gmtm(start_time, &tmp_tm);
	year = tmp_tm.tm_year + 1900;
	
	tzid = NULL;
	ptz_component = NULL;
	if (b_recurrence) {
		propname = {MNID_ID, PSETID_APPOINTMENT, PidLidTimeZoneStruct};
		if (!get_propids(&propnames, &propids))
			return FALSE;
		bin = pmsg->proplist.get<BINARY>(PROP_TAG(PT_BINARY, propids.ppropid[0]));
		if (bin != nullptr) {
			propname = {MNID_ID, PSETID_APPOINTMENT, PidLidTimeZoneDescription};
			if (!get_propids(&propnames, &propids))
				return FALSE;
			tzid = pmsg->proplist.get<char>(PROP_TAG(PT_UNICODE, propids.ppropid[0]));
			if (NULL == tzid) {
				goto EXPORT_TZDEFINITION;
			}
			ext_pull.init(bin->pb, bin->cb, alloc, 0);
			if (ext_pull.g_tzstruct(&tz_struct) != EXT_ERR_SUCCESS)
				return FALSE;
			ptz_component = oxcical_export_timezone(
					pical, year - 1, tzid, &tz_struct);
			if (ptz_component == nullptr)
				return FALSE;
		} else {
 EXPORT_TZDEFINITION:
			propname = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentTimeZoneDefinitionRecur};
			if (!get_propids(&propnames, &propids))
				return FALSE;
			bin = pmsg->proplist.get<BINARY>(PROP_TAG(PT_BINARY, propids.ppropid[0]));
			if (bin != nullptr) {
				ext_pull.init(bin->pb, bin->cb, alloc, 0);
				if (ext_pull.g_tzdef(&tz_definition) != EXT_ERR_SUCCESS)
					return FALSE;
				tzid = tz_definition.keyname;
				oxcical_convert_to_tzstruct(&tz_definition, &tz_struct);
				ptz_component = oxcical_export_timezone(
						pical, year - 1, tzid, &tz_struct);
				if (ptz_component == nullptr)
					return FALSE;
			}
		}
	} else {
		propname = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentTimeZoneDefinitionStartDisplay};
		if (!get_propids(&propnames, &propids))
			return FALSE;
		bin = pmsg->proplist.get<BINARY>(PROP_TAG(PT_BINARY, propids.ppropid[0]));
		if (bin != nullptr) {
			propname.lid = PidLidAppointmentTimeZoneDefinitionEndDisplay;
			if (!get_propids(&propnames, &propids))
				return FALSE;
			bin = pmsg->proplist.get<BINARY>(PROP_TAG(PT_BINARY, propids.ppropid[0]));
		}
		if (bin != nullptr) {
			ext_pull.init(bin->pb, bin->cb, alloc, 0);
			if (ext_pull.g_tzdef(&tz_definition) != EXT_ERR_SUCCESS)
				return FALSE;
			tzid = tz_definition.keyname;
			oxcical_convert_to_tzstruct(&tz_definition, &tz_struct);
			ptz_component = oxcical_export_timezone(
					pical, year - 1, tzid, &tz_struct);
			if (ptz_component == nullptr)
				return FALSE;
		}
	}
	
 EXPORT_VEVENT:
	propname = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentSubType};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	auto snum = pmsg->proplist.get<const uint8_t>(PROP_TAG(PT_BOOLEAN, propids.ppropid[0]));
	BOOL b_allday = snum != nullptr && *snum != 0 ? TRUE : false;
	auto pcomponent = ical_new_component("VEVENT");
	if (pcomponent == nullptr)
		return FALSE;
	pical.append_comp(pcomponent);
	
	if (0 == strcmp(method, "REQUEST") ||
		0 == strcmp(method, "CANCEL")) {
		str = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
		if (str != nullptr) {
			str = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_ADDRTYPE);
			if (str != nullptr) {
				if (strcasecmp(str, "SMTP") == 0) {
					str = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
				} else if (strcasecmp(str, "EX") == 0) {
					str = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
					if (str != nullptr)
						str = !essdn_to_username(str, tmp_buff, std::size(tmp_buff)) ?
						      nullptr : tmp_buff;
				} else {
					str = nullptr;
				}
			}
		}
		if (str != nullptr) {
			snprintf(tmp_buff1, sizeof(tmp_buff1), "MAILTO:%s", str);
			piline = ical_new_simple_line("ORGANIZER", tmp_buff1);
			if (piline == nullptr)
				return FALSE;
			if (pcomponent->append_line(piline) < 0)
				return false;
			str = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_NAME);
			if (str != nullptr) {
				piline->append_param("CN", str);
			}
		}
	}
	
	if (!oxcical_export_recipient_table(*pcomponent, entryid_to_username,
	    essdn_to_username, alloc, partstat, pmsg))
		return FALSE;
	
	str = pmsg->proplist.get<char>(PR_BODY);
	if (str != nullptr) {
		auto kw = strcmp(method, "REPLY") == 0 ||
		          strcmp(method, "COUNTER") == 0 ?
		          "COMMENT" : "DESCRIPTION";
		piline = ical_new_simple_line(kw, str);
		if (piline == nullptr)
			return FALSE;
		if (pcomponent->append_line(piline) < 0)
			return false;
		if (NULL != planguage) {
			piline->append_param("LANGUAGE", planguage);
		}
	}
	
	if (!b_exceptional && b_recurrence) {
		if (!oxcical_export_rrule(*ptz_component, *pcomponent, &apprecurr))
			return FALSE;
		if (oxcical_check_exdate(&apprecurr) &&
		    !oxcical_export_exdate(tzid, g_oxcical_allday_ymd,
		    *pcomponent, &apprecurr))
			return FALSE;
		if (oxcical_check_rdate(&apprecurr) &&
		    !oxcical_export_rdate(tzid, g_oxcical_allday_ymd,
		    *pcomponent, &apprecurr))
			return FALSE;
	}
	
	propname = {MNID_ID, PSETID_MEETING, PidLidGlobalObjectId};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	bin = pmsg->proplist.get<BINARY>(PROP_TAG(PT_BINARY, propids.ppropid[0]));
	if (bin != nullptr) {
		ext_pull.init(bin->pb, bin->cb, alloc, 0);
		if (ext_pull.g_goid(&globalobjectid) != EXT_ERR_SUCCESS)
			return FALSE;
		if (globalobjectid.data.pb != nullptr &&
		    globalobjectid.data.cb >= 12 &&
		    memcmp(globalobjectid.data.pb, ThirdPartyGlobalId, 12) == 0) {
			if (globalobjectid.data.cb - 12 > sizeof(tmp_buff) - 1) {
				memcpy(tmp_buff, globalobjectid.data.pb + 12,
									sizeof(tmp_buff) - 1);
				tmp_buff[sizeof(tmp_buff) - 1] = '\0';
			} else {
				memcpy(tmp_buff, globalobjectid.data.pb + 12,
								globalobjectid.data.cb - 12);
				tmp_buff[globalobjectid.data.cb - 12] = '\0';
			}
			piline = ical_new_simple_line("UID", tmp_buff);
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
			piline = ical_new_simple_line("UID", tmp_buff1);
		}
		if (piline == nullptr)
			return FALSE;
		if (pcomponent->append_line(piline) < 0)
			return false;
	} else {
		time(&cur_time);
		memset(&globalobjectid, 0, sizeof(GLOBALOBJECTID));
		globalobjectid.arrayid = EncodedGlobalId;
		globalobjectid.creationtime = rop_util_unix_to_nttime(cur_time);
		globalobjectid.data.cb = 16;
		globalobjectid.data.pc = tmp_buff1;
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
		piline = ical_new_simple_line("UID", tmp_buff1);
		if (piline == nullptr)
			return FALSE;
		if (pcomponent->append_line(piline) < 0)
			return false;
	}
	
	propname = {MNID_ID, PSETID_APPOINTMENT, PidLidExceptionReplaceTime};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	auto proptag_xrt = PROP_TAG(PT_SYSTIME, propids.ppropid[0]);
	lnum = pmsg->proplist.get<uint64_t>(proptag_xrt);
	if (lnum == nullptr) {
		propname = {MNID_ID, PSETID_MEETING, PidLidIsException};
		if (!get_propids(&propnames, &propids))
			return FALSE;
		auto flag = pmsg->proplist.get<const uint8_t>(PROP_TAG(PT_BOOLEAN, propids.ppropid[0]));
		if (flag != nullptr && *flag != 0) {
			propname = {MNID_ID, PSETID_MEETING, PidLidStartRecurrenceTime};
			if (!get_propids(&propnames, &propids))
				return FALSE;
			num = pmsg->proplist.get<const uint32_t>(PROP_TAG(PT_LONG, propids.ppropid[0]));
			if (num != nullptr) {
				itime.hour   = (*num >> 12) & 0x1f;
				itime.minute = (*num >> 6) & 0x3f;
				itime.second = *num & 0x3f;
				propname.lid = PidLidGlobalObjectId;
				if (!get_propids(&propnames, &propids))
					return FALSE;
				bin = pmsg->proplist.get<BINARY>(PROP_TAG(PT_BINARY, propids.ppropid[0]));
				if (bin != nullptr) {
					ext_pull.init(bin->pb, bin->cb, alloc, 0);
					if (ext_pull.g_goid(&globalobjectid) != EXT_ERR_SUCCESS)
						return FALSE;
					itime.year = globalobjectid.year;
					itime.month = globalobjectid.month;
					itime.day = globalobjectid.day;
				}
			}
		}
	} else {
		if (!ical_utc_to_datetime(ptz_component.get(),
		    rop_util_nttime_to_unix(*lnum), &itime))
			return FALSE;
	}
	if (lnum == nullptr) {
		if (b_exceptional)
			return FALSE;
	} else if (!b_allday) {
		if (NULL == ptz_component) {
			sprintf_dtutc(tmp_buff, std::size(tmp_buff), itime);
		} else {
			sprintf_dtlcl(tmp_buff, std::size(tmp_buff), itime);
		}
		piline = ical_new_simple_line("RECURRENCE-ID", tmp_buff);
		if (piline == nullptr)
			return FALSE;
		if (pcomponent->append_line(piline) < 0)
			return false;
		if (NULL != ptz_component) {
			piline->append_param("TZID", tzid);
		}
	} else {
		sprintf_dt(tmp_buff, std::size(tmp_buff), itime);
		piline = ical_new_simple_line("RECURRENCE-ID", tmp_buff);
		if (piline == nullptr)
			return FALSE;
		if (pcomponent->append_line(piline) < 0)
			return false;
	}
	
	str = pmsg->proplist.get<char>(PR_SUBJECT);
	if (str != nullptr) {
		piline = ical_new_simple_line("SUMMARY", str);
		if (piline == nullptr)
			return FALSE;
		if (pcomponent->append_line(piline) < 0)
			return false;
		if (NULL != planguage) {
			piline->append_param("LANGUAGE", planguage);
		}
	}
	
	if (!ical_utc_to_datetime(ptz_component.get(), start_time, &itime))
		return FALSE;
	if (ptz_component != nullptr)
		sprintf_dtlcl(tmp_buff, std::size(tmp_buff), itime);
	else if (g_oxcical_allday_ymd)
		sprintf_dt(tmp_buff, std::size(tmp_buff), itime);
	else
		sprintf_dtutc(tmp_buff, std::size(tmp_buff), itime);

	piline = ical_new_simple_line("DTSTART", tmp_buff);
	if (piline == nullptr)
		return FALSE;
	if (pcomponent->append_line(piline) < 0)
		return false;
	if (ptz_component == nullptr && g_oxcical_allday_ymd) {
		piline->append_param("VALUE", "DATE");
	}
	if (NULL != ptz_component) {
		piline->append_param("TZID", tzid);
	}
	
	if (start_time != end_time) {
		if (!ical_utc_to_datetime(ptz_component.get(), end_time, &itime))
			return FALSE;
		if (ptz_component != nullptr)
			sprintf_dtlcl(tmp_buff, std::size(tmp_buff), itime);
		else if (g_oxcical_allday_ymd)
			sprintf_dt(tmp_buff, std::size(tmp_buff), itime);
		else
			sprintf_dtutc(tmp_buff, std::size(tmp_buff), itime);
		piline = ical_new_simple_line("DTEND", tmp_buff);
		if (piline == nullptr)
			return FALSE;
		if (pcomponent->append_line(piline) < 0)
			return false;
		if (ptz_component == nullptr && g_oxcical_allday_ymd) {
			piline->append_param("VALUE", "DATE");
		}
		if (NULL != ptz_component) {
			piline->append_param("TZID", tzid);
		}
	}
	
	propname = {MNID_STRING, PS_PUBLIC_STRINGS, 0, deconst(PidNameKeywords)};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	auto sa = pmsg->proplist.get<const STRING_ARRAY>(PROP_TAG(PT_MV_UNICODE, propids.ppropid[0]));
	if (sa != nullptr) {
		piline = ical_new_line("CATEGORIES");
		if (piline == nullptr)
			return FALSE;
		if (pical.append_line(piline) < 0)
			return false;
		auto &pivalue = piline->append_value();
		for (size_t i = 0; i < sa->count; ++i)
			pivalue.append_subval(sa->ppstr[i]);
	}
	
	num = pmsg->proplist.get<uint32_t>(PR_SENSITIVITY);
	if (num == nullptr) {
		piline = ical_new_simple_line("CLASS", "PUBLIC");
	} else {
		switch (*num) {
		case SENSITIVITY_PERSONAL:
			piline = ical_new_simple_line("CLASS", "PERSONAL");
			break;
		case SENSITIVITY_PRIVATE:
			piline = ical_new_simple_line("CLASS", "PRIVATE");
			break;
		case SENSITIVITY_COMPANY_CONFIDENTIAL:
			piline = ical_new_simple_line("CLASS", "CONFIDENTIAL");
			break;
		default:
			piline = ical_new_simple_line("CLASS", "PUBLIC");
			break;
		}
	}
	if (piline == nullptr)
		return FALSE;
	if (pcomponent->append_line(piline) < 0)
		return false;
	
	snum = pmsg->proplist.get<const uint8_t>(PR_IMPORTANCE);
	if (snum != nullptr) {
		/* RFC 5545 §3.8.1.9 / MS-OXCICAL v13 §2.1.3.1.1.20.17 pg 58 */
		switch (*snum) {
		case IMPORTANCE_NORMAL:
			piline = ical_new_simple_line("PRIORITY", "5");
			break;
		case IMPORTANCE_HIGH:
			piline = ical_new_simple_line("PRIORITY", "1");
			break;
		default:
			piline = ical_new_simple_line("PRIORITY", "9");
			break;
		}
		if (piline == nullptr)
			return FALSE;
		if (pcomponent->append_line(piline) < 0)
			return false;
	}
	
	propname = {MNID_ID, PSETID_MEETING};
	propname.lid = (strcmp(method, "REPLY") == 0 || strcmp(method, "COUNTER") == 0) ?
	               PidLidAttendeeCriticalChange : PidLidOwnerCriticalChange;
	if (!get_propids(&propnames, &propids))
		return FALSE;
	lnum = pmsg->proplist.get<uint64_t>(PROP_TAG(PT_SYSTIME, propids.ppropid[0]));
	if (lnum != nullptr) {
		ical_utc_to_datetime(nullptr, rop_util_nttime_to_unix(*lnum), &itime);
		sprintf_dtutc(tmp_buff, std::size(tmp_buff), itime);
		piline = ical_new_simple_line("DTSTAMP", tmp_buff);
		if (piline == nullptr)
			return FALSE;
		if (pcomponent->append_line(piline) < 0)
			return false;
	}
	
	propname = {MNID_ID, PSETID_APPOINTMENT, PidLidBusyStatus};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	auto pbusystatus = pmsg->proplist.get<uint32_t>(PROP_TAG(PT_LONG, propids.ppropid[0]));
	if (NULL != pbusystatus) {
		switch (static_cast<ol_busy_status>(*pbusystatus)) {
		case olFree:
		case olWorkingElsewhere:
			piline = ical_new_simple_line("TRANSP", "TRANSPARENT");
			if (piline == nullptr)
				return FALSE;
			if (pcomponent->append_line(piline) < 0)
				return false;
			break;
		case olTentative:
		case olBusy:
		case olOutOfOffice:
			piline = ical_new_simple_line("TRANSP", "OPAQUE");
			if (piline == nullptr)
				return FALSE;
			if (pcomponent->append_line(piline) < 0)
				return false;
			break;
		default:
			break;
		}
	}
	
	propname = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentSequence};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	auto psequence = pmsg->proplist.get<uint32_t>(PROP_TAG(PT_LONG, propids.ppropid[0]));
	if (NULL != psequence) {
		snprintf(tmp_buff, arsizeof(tmp_buff), "%u", *psequence);
		piline = ical_new_simple_line("SEQUENCE", tmp_buff);
		if (piline == nullptr)
			return FALSE;
		if (pcomponent->append_line(piline) < 0)
			return false;
	}
	
	propname = {MNID_ID, PSETID_APPOINTMENT, PidLidLocation};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	str = pmsg->proplist.get<char>(PROP_TAG(PT_UNICODE, propids.ppropid[0]));
	if (str != nullptr) {
		piline = ical_new_simple_line("LOCATION", str);
		if (piline == nullptr)
			return FALSE;
		if (pcomponent->append_line(piline) < 0)
			return false;
		propname = {MNID_STRING, PS_PUBLIC_STRINGS, 0, deconst(PidNameLocationUrl)};
		if (!get_propids(&propnames, &propids))
			return FALSE;
		str = pmsg->proplist.get<char>(PROP_TAG(PT_UNICODE, propids.ppropid[0]));
		if (str != nullptr) {
			piline->append_param("ALTREP", str);
		}
		if (NULL != planguage) {
			piline->append_param("LANGUAGE", planguage);
		}
	}
	
	if (NULL != psequence) {
		snprintf(tmp_buff, arsizeof(tmp_buff), "%u", *psequence);
		piline = ical_new_simple_line(
			"X-MICROSOFT-CDO-APPT-SEQUENCE", tmp_buff);
		if (piline == nullptr)
			return FALSE;
		if (pcomponent->append_line(piline) < 0)
			return false;
	}
	
	num = pmsg->proplist.get<uint32_t>(PR_OWNER_APPT_ID);
	if (num != nullptr) {
		snprintf(tmp_buff, arsizeof(tmp_buff), "%u", *num);
		piline = ical_new_simple_line(
			"X-MICROSOFT-CDO-OWNERAPPTID", tmp_buff);
		if (piline == nullptr)
			return FALSE;
		if (pcomponent->append_line(piline) < 0)
			return false;
	}
	
	if (pbusystatus != nullptr && !busystatus_to_line(static_cast<ol_busy_status>(*pbusystatus),
	    "X-MICROSOFT-CDO-BUSYSTATUS", pcomponent.get()))
		return false;

	propname = {MNID_ID, PSETID_APPOINTMENT, PidLidIntendedBusyStatus};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	num = pmsg->proplist.get<uint32_t>(PROP_TAG(PT_LONG, propids.ppropid[0]));
	if (num != nullptr && !busystatus_to_line(static_cast<ol_busy_status>(*num),
	    "X-MICROSOFT-CDO-INTENDEDSTATUS", pcomponent.get()))
		return false;

	piline = ical_new_simple_line("X-MICROSOFT-CDO-ALLDAYEVENT", b_allday ? "TRUE" : "FALSE");
	if (piline == nullptr)
		return FALSE;
	if (pcomponent->append_line(piline) < 0)
		return false;
	
	num = pmsg->proplist.get<uint32_t>(PR_IMPORTANCE);
	if (num != nullptr) {
		switch (static_cast<mapi_importance>(*num)) {
		case IMPORTANCE_LOW:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-IMPORTANCE", "0");
			if (piline == nullptr)
				return FALSE;
			if (pcomponent->append_line(piline) < 0)
				return false;
			break;
		case IMPORTANCE_NORMAL:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-IMPORTANCE", "1");
			if (piline == nullptr)
				return FALSE;
			if (pcomponent->append_line(piline) < 0)
				return false;
			break;
		case IMPORTANCE_HIGH:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-IMPORTANCE", "2");
			if (piline == nullptr)
				return FALSE;
			if (pcomponent->append_line(piline) < 0)
				return false;
			break;
		default:
			break;
		}
	}
	
	piline = ical_new_simple_line("X-MICROSOFT-CDO-INSTTYPE", b_exceptional ? "3" : b_recurrence ? "1" : "0");
	if (piline == nullptr)
		return FALSE;
	if (pcomponent->append_line(piline) < 0)
		return false;
	
	propname = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentNotAllowPropose};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	auto flag = pmsg->proplist.get<uint8_t>(PROP_TAG(PT_BOOLEAN, propids.ppropid[0]));
	if (flag != nullptr) {
		if (*flag == 0)
			piline = ical_new_simple_line(
				"X-MICROSOFT-DISALLOW-COUNTER", "FALSE");
		else
			piline = ical_new_simple_line(
				"X-MICROSOFT-DISALLOW-COUNTER", "TRUE");
		if (piline == nullptr)
			return FALSE;
		if (pcomponent->append_line(piline) < 0)
			return false;
	}
	
	if (!b_exceptional && pmsg->children.pattachments != nullptr) {
		for (size_t i = 0; i < pmsg->children.pattachments->count; ++i) {
			if (NULL == pmsg->children.pattachments->pplist[i]->pembedded) {
				continue;
			}
			pembedded = pmsg->children.pattachments->pplist[i]->pembedded;
			str = pembedded->proplist.get<char>(PR_MESSAGE_CLASS);
			if (str == nullptr)
				str = pembedded->proplist.get<char>(PR_MESSAGE_CLASS_A);
			if (str == nullptr || strcasecmp(str,
			    "IPM.OLE.CLASS.{00061055-0000-0000-C000-000000000046}"))
				continue;
			if (!pembedded->proplist.has(proptag_xrt))
				continue;
			if (!oxcical_export_internal(method, tzid,
			    ptz_component, pembedded, pical, entryid_to_username,
			    essdn_to_username, alloc, get_propids))
				return FALSE;
		}
	}
	
	propname = {MNID_ID, PSETID_COMMON, PidLidReminderSet};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	flag = pmsg->proplist.get<uint8_t>(PROP_TAG(PT_BOOLEAN, propids.ppropid[0]));
	if (flag != nullptr && *flag != 0) {
		pcomponent = ical_new_component("VALARM");
		if (pcomponent == nullptr)
			return FALSE;
		pical.append_comp(pcomponent);
		piline = ical_new_simple_line("DESCRIPTION", "REMINDER");
		if (piline == nullptr)
			return FALSE;
		if (pcomponent->append_line(piline) < 0)
			return false;
		propname = {MNID_ID, PSETID_COMMON, PidLidReminderDelta};
		if (!get_propids(&propnames, &propids))
			return FALSE;
		num = pmsg->proplist.get<uint32_t>(PROP_TAG(PT_LONG, propids.ppropid[0]));
		if (num == nullptr || *num == 0x5AE980E1)
			strcpy(tmp_buff, "-PT15M");
		else
			snprintf(tmp_buff, arsizeof(tmp_buff), "-PT%uM", *num);
		piline = ical_new_simple_line("TRIGGER", tmp_buff);
		if (piline == nullptr)
			return FALSE;
		if (pcomponent->append_line(piline) < 0)
			return false;
		piline->append_param("RELATED", "START");
		piline = ical_new_simple_line("ACTION", "DISPLAY");
		if (piline == nullptr)
			return FALSE;
		if (pcomponent->append_line(piline) < 0)
			return false;
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-2097: ENOMEM\n");
	return false;
}

BOOL oxcical_export(const MESSAGE_CONTENT *pmsg, ical &pical,
	EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
	ENTRYID_TO_USERNAME entryid_to_username,
	ESSDN_TO_USERNAME essdn_to_username)
{
	return oxcical_export_internal(nullptr, nullptr, nullptr, pmsg,
	       pical, entryid_to_username, essdn_to_username,
	       alloc, get_propids);
}
