// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cstdint>
#include <list>
#include <memory>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/tpropval_array.hpp>
#include <gromox/tarray_set.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/int_hash.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/oxcical.hpp>
#include <gromox/util.hpp>
#include <gromox/guid.hpp>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#define MAX_TZRULE_NUMBER						128

#define MAX_TZDEFINITION_LENGTH					(68*MAX_TZRULE_NUMBER+270)

struct UID_EVENTS {
	const char *puid;
	std::list<std::shared_ptr<ICAL_COMPONENT>> list;
};

static constexpr char EncodedGlobalId_hex[] =
	"040000008200E00074C5B7101A82E008";
static constexpr uint8_t EncodedGlobalId[16] =
	{0x04, 0x00, 0x00, 0x00, 0x82, 0x00, 0xE0, 0x00, 0x74, 0xC5, 0xB7, 0x10, 0x1A, 0x82, 0xE0, 0x08};
static constexpr uint8_t ThirdPartyGlobalId[12] =
	{0x76, 0x43, 0x61, 0x6c, 0x2d, 0x55, 0x69, 0x64, 0x01, 0x00, 0x00, 0x00};

static BOOL oxcical_parse_vtsubcomponent(std::shared_ptr<ICAL_COMPONENT> psub_component,
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
	auto piline = psub_component->get_line("TZOFFSETTO");
	if (NULL == piline) {
		return FALSE;
	}
	pvalue = piline->get_first_subvalue();
	if (NULL == pvalue) {
		return FALSE;
	}
	if (!ical_parse_utc_offset(pvalue, &hour, &minute))
		return FALSE;
	*pbias = 60*hour + minute;
	piline = psub_component->get_line("DTSTART");
	if (NULL == piline) {
		return FALSE;
	}
	if (piline->get_first_paramval("TZID") != nullptr)
		return FALSE;
	pvalue = piline->get_first_subvalue();
	if (NULL == pvalue) {
		return FALSE;
	}
	bool b_utc;
	if (!ical_parse_datetime(pvalue, &b_utc, &itime) || b_utc)
		return FALSE;
	*pyear = itime.year;
	pdate->hour = itime.hour;
	pdate->minute = itime.minute;
	pdate->second = itime.second;
	piline = psub_component->get_line("RRULE");
	if (NULL != piline) {
		pvalue = piline->get_first_subvalue_by_name("FREQ");
		if (NULL == pvalue || 0 != strcasecmp(pvalue, "YEARLY")) {
			return FALSE;
		}
		pvalue = piline->get_first_subvalue_by_name("BYDAY");
		pvalue1 = piline->get_first_subvalue_by_name("BYMONTHDAY");
		if ((NULL == pvalue && NULL == pvalue1) ||
			(NULL != pvalue && NULL != pvalue1)) {
			return FALSE;
		}
		pvalue2 = piline->get_first_subvalue_by_name("BYMONTH");
		if (NULL == pvalue2) {
			pdate->month = itime.month;
		} else {
			pdate->month = atoi(pvalue2);
			if (pdate->month < 1 || pdate->month > 12) {
				return FALSE;
			}
		}
		if (NULL != pvalue) {
			pdate->year = 0;
			if (!ical_parse_byday(pvalue, &dayofweek, &weekorder))
				return FALSE;
			if (-1 == weekorder) {
				weekorder = 5;
			}
			if (weekorder > 5 || weekorder < 1) {
				return FALSE;
			}
			pdate->dayofweek = dayofweek;
			pdate->day = weekorder;
		} else {
			pdate->year = 1;
			pdate->dayofweek = 0;
			pdate->day = atoi(pvalue1);
			if (abs(pdate->day) < 1 || abs(pdate->day) > 31) {
				return FALSE;
			}
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

static int oxcical_cmp_tzrule(const void *prule1, const void *prule2)
{
	auto a = static_cast<const TZRULE *>(prule1);
	auto b = static_cast<const TZRULE *>(prule2);
	return a->year == b->year ? 0 : a->year < b->year ? -1 : 1;
}

static BOOL oxcical_parse_tzdefinition(std::shared_ptr<ICAL_COMPONENT> pvt_component,
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
	auto piline = pvt_component->get_line("TZID");
	if (NULL == piline) {
		return FALSE;
	}
	ptz_definition->keyname = deconst(piline->get_first_subvalue());
	if (NULL == ptz_definition->keyname) {
		return FALSE;
	}
	ptz_definition->crules = 0;
	for (auto pcomponent : pvt_component->component_list) {
		if (strcasecmp(pcomponent->name.c_str(), "STANDARD") == 0) {
			b_daylight = FALSE;
		} else if (strcasecmp(pcomponent->name.c_str(), "DAYLIGHT") == 0) {
			b_daylight = TRUE;
		} else {
			continue;
		}
		if (FALSE == oxcical_parse_vtsubcomponent(
			pcomponent, &bias, &year, &date)) {
			return FALSE;
		}
		b_found = FALSE;
		for (i=0; i<ptz_definition->crules; i++) {
			if (year == ptz_definition->prules[i].year) {
				b_found = TRUE;
				break;
			}
		}
		if (FALSE == b_found) {
			if (ptz_definition->crules >= MAX_TZRULE_NUMBER) {
				return FALSE;
			}
			ptz_definition->crules ++;
			memset(ptz_definition->prules + i, 0, sizeof(TZRULE));
			ptz_definition->prules[i].major = 2;
			ptz_definition->prules[i].minor = 1;
			ptz_definition->prules[i].reserved = 0x003E;
			ptz_definition->prules[i].year = year;
		}
		if (TRUE == b_daylight) {
			ptz_definition->prules[i].daylightbias = bias;
			ptz_definition->prules[i].daylightdate = date;
		} else {
			ptz_definition->prules[i].bias = bias;
			ptz_definition->prules[i].standarddate = date;
		}
	}
	if (0 == ptz_definition->crules) {
		return FALSE;
	}
	qsort(ptz_definition->prules, ptz_definition->crules,
		sizeof(TZRULE), oxcical_cmp_tzrule);
	pstandard_rule = NULL;
	pdaylight_rule = NULL;
	for (i=0; i<ptz_definition->crules; i++) {
		if (0 != ptz_definition->prules[i].standarddate.month) {
			pstandard_rule = ptz_definition->prules + i;
		} else {
			if (NULL != pstandard_rule) {
				ptz_definition->prules[i].standarddate =
							pstandard_rule->standarddate;
				ptz_definition->prules[i].bias =
							pstandard_rule->bias;
			}
		}
		if (0 != ptz_definition->prules[i].daylightdate.month) {
			pdaylight_rule = ptz_definition->prules + i;
		} else {
			if (NULL != pdaylight_rule) {
				ptz_definition->prules[i].daylightdate =
							pstandard_rule->daylightdate;
				ptz_definition->prules[i].daylightbias =
							pstandard_rule->daylightbias;
			}
		}
		/* ignore the definition which has only STANDARD component 
			or whith the same STANDARD and DAYLIGHT component */
		if (0 == ptz_definition->prules[i].daylightdate.month ||
			0 == memcmp(&ptz_definition->prules[i].standarddate,
				&ptz_definition->prules[i].daylightdate,
				sizeof(SYSTEMTIME))) {
			memset(&ptz_definition->prules[i].daylightdate,
				0, sizeof(SYSTEMTIME));
		}
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
	int i;
	EXT_PUSH ext_push;
	
	ext_buffer_push_init(&ext_push, pbin->pb, MAX_TZDEFINITION_LENGTH, 0);
	for (i=0; i<ptz_definition->crules; i++) {
		ptz_definition->prules[i].flags = tzrule_flags;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_timezonedefinition(
		&ext_push, ptz_definition)) {
		return FALSE;
	}
	pbin->cb = ext_push.offset;
	return TRUE;
}

static BOOL oxcical_timezonestruct_to_binary(
	TIMEZONESTRUCT *ptzstruct, BINARY *pbin)
{
	EXT_PUSH ext_push;
	
	ext_buffer_push_init(&ext_push, pbin->pb, 256, 0);
	if (EXT_ERR_SUCCESS != ext_buffer_push_timezonestruct(
		&ext_push, ptzstruct)) {
		return FALSE;
	}
	pbin->cb = ext_push.offset;
	return TRUE;
}

/* ptz_component can be NULL, represents UTC */
static BOOL oxcical_parse_rrule(std::shared_ptr<ICAL_COMPONENT> ptz_component,
    std::shared_ptr<ICAL_LINE> piline, uint16_t calendartype, time_t start_time,
	uint32_t duration_minutes, APPOINTMENTRECURRENCEPATTERN *papprecurr)
{
	int tmp_int;
	time_t tmp_time;
	ICAL_TIME itime;
	ICAL_TIME itime1;
	ICAL_RRULE irrule;
	const char *pvalue;
	uint32_t patterntype;
	ICAL_TIME itime_base;
	ICAL_TIME itime_first;
	const ICAL_TIME *pitime;
	
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
		if (NULL != pvalue && atoi(pvalue) != start_time%60) {
			return FALSE;
		}
	}
	if (!ical_parse_rrule(ptz_component, start_time, &piline->value_list, &irrule))
		return FALSE;
	auto b_exceptional = ical_rrule_exceptional(&irrule);
	if (b_exceptional)
		if (!ical_rrule_iterate(&irrule))
			return FALSE;
	itime_base = ical_rrule_base_itime(&irrule);
	itime_first = ical_rrule_instance_itime(&irrule);
	papprecurr->readerversion2 = 0x00003006;
	papprecurr->writerversion2 = 0x00003009;
	papprecurr->recurrencepattern.readerversion = 0x3004;
	papprecurr->recurrencepattern.writerversion = 0x3004;
	papprecurr->recurrencepattern.slidingflag = 0x00000000;
	papprecurr->recurrencepattern.firstdow =
						ical_rrule_weekstart(&irrule);
	itime = ical_rrule_instance_itime(&irrule);
	papprecurr->starttimeoffset = 60*itime.hour + itime.minute;
	papprecurr->endtimeoffset =
		papprecurr->starttimeoffset + duration_minutes;
	itime.hour = 0;
	itime.minute = 0;
	itime.second = 0;
	ical_itime_to_utc(ptz_component, itime, &tmp_time);
	papprecurr->recurrencepattern.startdate =
			rop_util_unix_to_nttime(tmp_time)/600000000;
	if (ical_rrule_endless(&irrule)) {
 SET_INFINITE:
		papprecurr->recurrencepattern.endtype = ENDTYPE_NEVER_END;
		papprecurr->recurrencepattern.occurrencecount = 0x0000000A;
		papprecurr->recurrencepattern.enddate = ENDDATE_MISSING;
	} else {
		itime = ical_rrule_instance_itime(&irrule);
		while (ical_rrule_iterate(&irrule)) {
			itime1 = ical_rrule_instance_itime(&irrule);
			if (itime1.year > 4500) {
				goto SET_INFINITE;
			}
			/* instances can not be in same day */
			if (itime1.year == itime.year &&
				itime1.month == itime.month &&
				itime1.day == itime.day) {
				return FALSE;
			}
			itime = itime1;
		}
		if (0 != ical_rrule_total_count(&irrule)) {
			papprecurr->recurrencepattern.endtype =
						ENDTYPE_AFTER_N_OCCURRENCES;
			papprecurr->recurrencepattern.occurrencecount =
							ical_rrule_total_count(&irrule);
		} else {
			papprecurr->recurrencepattern.endtype =
								ENDTYPE_AFTER_DATE;
			papprecurr->recurrencepattern.occurrencecount =
								ical_rrule_sequence(&irrule);
		}
		if (b_exceptional)
			papprecurr->recurrencepattern.occurrencecount --;
		pitime = ical_rrule_until_itime(&irrule);
		if (NULL != pitime) {
			itime = *pitime;
		} else {
			itime = ical_rrule_instance_itime(&irrule);
		}
		itime.hour = 0;
		itime.minute = 0;
		itime.second = 0;
		ical_itime_to_utc(ptz_component, itime, &tmp_time);
		papprecurr->recurrencepattern.enddate =
			rop_util_unix_to_nttime(tmp_time)/600000000;
	}
	switch (ical_rrule_frequency(&irrule)) {
	case ICAL_FREQUENCY_SECOND:
	case ICAL_FREQUENCY_MINUTE:
	case ICAL_FREQUENCY_HOUR:
		return FALSE;
	case ICAL_FREQUENCY_DAY:
		if (piline->get_subval_list("BYDAY") != nullptr ||
		    piline->get_subval_list("BYMONTH") != nullptr ||
		    piline->get_subval_list("BYSETPOS") != nullptr)
			return FALSE;
		papprecurr->recurrencepattern.recurfrequency =
									RECURFREQUENCY_DAILY;
		if (ical_rrule_interval(&irrule) > 999) {
			return FALSE;
		}
		papprecurr->recurrencepattern.period =
				ical_rrule_interval(&irrule)*1440;
		papprecurr->recurrencepattern.firstdatetime =
			papprecurr->recurrencepattern.startdate %
			papprecurr->recurrencepattern.period;
		patterntype = PATTERNTYPE_DAY;
		break;
	case ICAL_FREQUENCY_WEEK:
		if (piline->get_subval_list("BYMONTH") != nullptr ||
		    piline->get_subval_list("BYSETPOS") != nullptr)
			return FALSE;
		papprecurr->recurrencepattern.recurfrequency =
								RECURFREQUENCY_WEEKLY;
		if (ical_rrule_interval(&irrule) > 99) {
			return FALSE;
		}
		papprecurr->recurrencepattern.period =
					ical_rrule_interval(&irrule);
		itime = itime_base;
		itime.hour = 0;
		itime.minute = 0;
		itime.second = 0;
		itime.leap_second = 0;
		ical_itime_to_utc(NULL, itime, &tmp_time);
		papprecurr->recurrencepattern.firstdatetime =
			(rop_util_unix_to_nttime(tmp_time)/600000000)%
			(10080*ical_rrule_interval(&irrule));
		patterntype = PATTERNTYPE_WEEK;
		if (ical_rrule_check_bymask(&irrule, RRULE_BY_DAY)) {
			psubval_list = piline->get_subval_list("BYDAY");
			papprecurr->recurrencepattern.
				patterntypespecific.weekrecurrence = 0;
			for (const auto &pnv2 : *psubval_list) {
				auto wd = pnv2.has_value() ? pnv2->c_str() : "";
				if (strcasecmp(wd, "SU") == 0) {
					papprecurr->recurrencepattern.
						patterntypespecific.weekrecurrence |= 0x00000001;
				} else if (strcasecmp(wd, "MO") == 0) {
					papprecurr->recurrencepattern.
						patterntypespecific.weekrecurrence |= 0x00000002;
				} else if (strcasecmp(wd, "TU") == 0) {
					papprecurr->recurrencepattern.
						patterntypespecific.weekrecurrence |= 0x00000004;
				} else if (strcasecmp(wd, "WE") == 0) {
					papprecurr->recurrencepattern.
						patterntypespecific.weekrecurrence |= 0x00000008;
				} else if (strcasecmp(wd, "TH") == 0) {
					papprecurr->recurrencepattern.
						patterntypespecific.weekrecurrence |= 0x00000010;
				} else if (strcasecmp(wd, "FR") == 0) {
					papprecurr->recurrencepattern.
						patterntypespecific.weekrecurrence |= 0x00000020;
				} else if (strcasecmp(wd, "SA") == 0) {
					papprecurr->recurrencepattern.
						patterntypespecific.weekrecurrence |= 0x00000040;
				}
			}
		} else {
			ical_utc_to_datetime(ptz_component, start_time, &itime);
			papprecurr->recurrencepattern.
				patterntypespecific.weekrecurrence = ((uint32_t)1) <<
				ical_get_dayofweek(itime.year, itime.month, itime.day);
		}
		break;
	case ICAL_FREQUENCY_MONTH:
		if (piline->get_subval_list("BYMONTH") != nullptr)
			return FALSE;
		papprecurr->recurrencepattern.recurfrequency =
								RECURFREQUENCY_MONTHLY;
		if (ical_rrule_interval(&irrule) > 99) {
			return FALSE;
		}
		papprecurr->recurrencepattern.period =
					ical_rrule_interval(&irrule);
		memset(&itime, 0, sizeof(ICAL_TIME));
		itime.year = 1601;
		itime.month = ((itime_base.year - 1601)*12 + itime_base.month - 1)
										%ical_rrule_interval(&irrule) + 1;
		itime.year += itime.month/12;
		itime.month %= 12;
		itime.day = 1;
		memset(&itime1, 0, sizeof(ICAL_TIME));
		itime1.year = 1601;
		itime1.month = 1;
		itime1.day = 1;
		papprecurr->recurrencepattern.firstdatetime =
					ical_delta_day(itime, itime1)*1440;
		if (ical_rrule_check_bymask(&irrule, RRULE_BY_DAY) &&
		    ical_rrule_check_bymask(&irrule, RRULE_BY_SETPOS)) {
			patterntype = PATTERNTYPE_MONTHNTH;
			psubval_list = piline->get_subval_list("BYDAY");
			papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence = 0;
			for (const auto &pnv2 : *psubval_list) {
				auto wd = pnv2.has_value() ? pnv2->c_str() : "";
				if (strcasecmp(wd, "SU") == 0) {
					papprecurr->recurrencepattern.
								patterntypespecific.monthnth.
								weekrecurrence |= 0x00000001;
				} else if (strcasecmp(wd, "MO") == 0) {
					papprecurr->recurrencepattern.
								patterntypespecific.monthnth.
								weekrecurrence |= 0x00000002;
				} else if (strcasecmp(wd, "TU") == 0) {
					papprecurr->recurrencepattern.
								patterntypespecific.monthnth.
								weekrecurrence |= 0x00000004;
				} else if (strcasecmp(wd, "WE") == 0) {
					papprecurr->recurrencepattern.
								patterntypespecific.monthnth.
								weekrecurrence |= 0x00000008;
				} else if (strcasecmp(wd, "TH") == 0) {
					papprecurr->recurrencepattern.
								patterntypespecific.monthnth.
								weekrecurrence |= 0x00000010;
				} else if (strcasecmp(wd, "FR") == 0) {
					papprecurr->recurrencepattern.
								patterntypespecific.monthnth.
								weekrecurrence |= 0x00000020;
				} else if (strcasecmp(wd, "SA") == 0) {
					papprecurr->recurrencepattern.
								patterntypespecific.monthnth.
								weekrecurrence |= 0x00000040;
				}
			}
			pvalue = piline->get_first_subvalue_by_name("BYSETPOS");
			tmp_int = atoi(pvalue);
			if (tmp_int > 4 || tmp_int < -1) {
				return FALSE;
			} else if (-1 == tmp_int) {
				tmp_int = 5;
			}
			papprecurr->recurrencepattern.patterntypespecific.
							monthnth.recurrencenum = tmp_int;
		} else {
			if (ical_rrule_check_bymask(&irrule, RRULE_BY_DAY) ||
			    ical_rrule_check_bymask(&irrule, RRULE_BY_SETPOS))
				return FALSE;
			patterntype = PATTERNTYPE_MONTH;
			pvalue = piline->get_first_subvalue_by_name("BYMONTHDAY");
			if (NULL == pvalue) {
				ical_utc_to_datetime(ptz_component, start_time, &itime);
				tmp_int = itime.day;
			} else {
				tmp_int = atoi(pvalue);
				if (tmp_int < -1) {
					return FALSE;
				} else if (-1 == tmp_int) {
					tmp_int = 31;
				}
			}
			papprecurr->recurrencepattern.
				patterntypespecific.dayofmonth = tmp_int;
		}
		break;
	case ICAL_FREQUENCY_YEAR:
		papprecurr->recurrencepattern.recurfrequency =
								RECURFREQUENCY_YEARLY;
		if (ical_rrule_interval(&irrule) > 8) {
			return FALSE;
		}
		papprecurr->recurrencepattern.period =
				12*ical_rrule_interval(&irrule);
				
		memset(&itime, 0, sizeof(ICAL_TIME));
		itime.year = 1601;
		itime.month = (itime_first.month - 1)
			%(12*ical_rrule_interval(&irrule)) + 1;
		itime.year += itime.month/12;
		itime.month %= 12;
		itime.day = 1;
		memset(&itime1, 0, sizeof(ICAL_TIME));
		itime1.year = 1601;
		itime1.month = 1;
		itime1.day = 1;
		papprecurr->recurrencepattern.firstdatetime =
					ical_delta_day(itime, itime1)*1440;
		if (ical_rrule_check_bymask(&irrule, RRULE_BY_DAY) &&
		    ical_rrule_check_bymask(&irrule, RRULE_BY_SETPOS) &&
		    ical_rrule_check_bymask(&irrule, RRULE_BY_MONTH)) {
			if (ical_rrule_check_bymask(&irrule, RRULE_BY_MONTHDAY))
				return FALSE;
			patterntype = PATTERNTYPE_MONTHNTH;
			psubval_list = piline->get_subval_list("BYDAY");
			papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence = 0;
			for (const auto &pnv2 : *psubval_list) {
				auto wd = pnv2.has_value() ? pnv2->c_str() : "";
				if (strcasecmp(wd, "SU") == 0) {
					papprecurr->recurrencepattern.
						patterntypespecific.monthnth.
						weekrecurrence |= 0x00000001;
				} else if (strcasecmp(wd, "MO") == 0) {
					papprecurr->recurrencepattern.
						patterntypespecific.monthnth.
						weekrecurrence |= 0x00000002;
				} else if (strcasecmp(wd, "TU") == 0) {
					papprecurr->recurrencepattern.
						patterntypespecific.monthnth.
						weekrecurrence |= 0x00000004;
				} else if (strcasecmp(wd, "WE") == 0) {
					papprecurr->recurrencepattern.
						patterntypespecific.monthnth.
						weekrecurrence |= 0x00000008;
				} else if (strcasecmp(wd, "TH") == 0) {
					papprecurr->recurrencepattern.
						patterntypespecific.monthnth.
						weekrecurrence |= 0x00000010;
				} else if (strcasecmp(wd, "FR") == 0) {
					papprecurr->recurrencepattern.
						patterntypespecific.monthnth.
						weekrecurrence |= 0x00000020;
				} else if (strcasecmp(wd, "SA") == 0) {
					papprecurr->recurrencepattern.
						patterntypespecific.monthnth.
						weekrecurrence |= 0x00000040;
				}
			}
			pvalue = piline->get_first_subvalue_by_name("BYSETPOS");
			tmp_int = atoi(pvalue);
			if (tmp_int > 4 || tmp_int < -1) {
				return FALSE;
			} else if (-1 == tmp_int) {
				tmp_int = 5;
			}
			papprecurr->recurrencepattern.patterntypespecific.
							monthnth.recurrencenum = tmp_int;
		} else {
			if (ical_rrule_check_bymask(&irrule, RRULE_BY_DAY) ||
			    ical_rrule_check_bymask(&irrule, RRULE_BY_SETPOS))
				return FALSE;
			patterntype = PATTERNTYPE_MONTH;
			pvalue = piline->get_first_subvalue_by_name("BYMONTHDAY");
			if (NULL == pvalue) {
				ical_utc_to_datetime(ptz_component, start_time, &itime);
				tmp_int = itime.day;
			} else {
				tmp_int = atoi(pvalue);
				if (tmp_int < -1) {
					return FALSE;
				} else if (-1 == tmp_int) {
					tmp_int = 31;
				}
			}
			papprecurr->recurrencepattern.
				patterntypespecific.dayofmonth = tmp_int;
		}
		break;
	}
	if (CALENDARTYPE_HIJRI == calendartype) {
		if (PATTERNTYPE_MONTH == patterntype) {
			patterntype = PATTERNTYPE_HJMONTH;
			calendartype = CALENDARTYPE_DEFAULT;
		} else if (PATTERNTYPE_MONTHNTH == patterntype) {
			patterntype = PATTERNTYPE_HJMONTHNTH;
			calendartype = CALENDARTYPE_DEFAULT;
		}
	}
	papprecurr->recurrencepattern.patterntype = patterntype;
	papprecurr->recurrencepattern.calendartype = calendartype;
	return TRUE;
}

static std::shared_ptr<ICAL_COMPONENT> oxcical_find_vtimezone(ICAL *pical, const char *tzid)
{
	const char *pvalue;
	
	for (auto pcomponent : pical->component_list) {
		if (strcasecmp(pcomponent->name.c_str(), "VTIMEZONE") != 0)
			continue;
		auto piline = pcomponent->get_line("TZID");
		if (NULL == piline) {
			continue;
		}
		pvalue = piline->get_first_subvalue();
		if (NULL == pvalue) {
			continue;
		}
		if (0 == strcasecmp(pvalue, tzid)) {
			return pcomponent;
		}
	}
	return NULL;
}

static BOOL oxcical_parse_tzdisplay(BOOL b_dtstart,
    std::shared_ptr<ICAL_COMPONENT> ptz_component, INT_HASH_TABLE *phash,
	uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	static const uint32_t lid1 = 0x0000825E; /* PidLidAppointmentTimeZoneDefinitionStartDisplay */
	static const uint32_t lid2 = 0x0000825F; /* PidLidAppointmentTimeZoneDefinitionEndDisplay */
	TAGGED_PROPVAL propval;
	PROPERTY_NAME propname;
	TIMEZONEDEFINITION tz_definition;
	TZRULE rules_buff[MAX_TZRULE_NUMBER];
	uint8_t bin_buff[MAX_TZDEFINITION_LENGTH];
	
	tz_definition.prules = rules_buff;
	if (FALSE == oxcical_parse_tzdefinition(
		ptz_component, &tz_definition)) {
		return FALSE;
	}
	tmp_bin.pb = bin_buff;
	tmp_bin.cb = 0;
	if (FALSE == oxcical_tzdefinition_to_binary(
		&tz_definition, TZRULE_FLAG_EFFECTIVE_TZREG, &tmp_bin)) {
		return FALSE;
	}
	propname.kind = MNID_ID;
	propname.plid = deconst(b_dtstart ? &lid1 : &lid2);
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_BINARY, *plast_propid);
	propval.pvalue = &tmp_bin;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_recurring_timezone(std::shared_ptr<ICAL_COMPONENT> ptz_component,
    INT_HASH_TABLE *phash, uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	const char *ptzid;
	static uint32_t lid;
	static uint32_t lid1;
	static uint32_t lid2;
	TAGGED_PROPVAL propval;
	PROPERTY_NAME propname;
	TIMEZONESTRUCT tz_struct;
	TIMEZONEDEFINITION tz_definition;
	TZRULE rules_buff[MAX_TZRULE_NUMBER];
	uint8_t bin_buff[MAX_TZDEFINITION_LENGTH];
	
	tz_definition.prules = rules_buff;
	if (FALSE == oxcical_parse_tzdefinition(
		ptz_component, &tz_definition)) {
		return FALSE;
	}
	auto piline = ptz_component->get_line("TZID");
	if (NULL == piline) {
		return FALSE;
	}
	ptzid = piline->get_first_subvalue();
	if (NULL == ptzid) {
		return FALSE;
	}
	/* PidLidTimeZoneDescription */
	lid = 0x00008234;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_UNICODE, *plast_propid);
	propval.pvalue = deconst(ptzid);
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	oxcical_convert_to_tzstruct(&tz_definition, &tz_struct);
	tmp_bin.pb = bin_buff;
	tmp_bin.cb = 0;
	if (FALSE == oxcical_timezonestruct_to_binary(
		&tz_struct, &tmp_bin)) {
		return FALSE;
	}
	/* PidLidTimeZoneStruct */
	lid1 = 0x00008233;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid1;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_BINARY, *plast_propid);
	propval.pvalue = &tmp_bin;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	tmp_bin.pb = bin_buff;
	tmp_bin.cb = 0;
	if (FALSE == oxcical_tzdefinition_to_binary(
		&tz_definition, TZRULE_FLAG_EFFECTIVE_TZREG|
		TZRULE_FLAG_RECUR_CURRENT_TZREG, &tmp_bin)) {
		return FALSE;
	}
	/* PidLidAppointmentTimeZoneDefinitionRecur */
	lid2 = 0x00008260;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid2;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_BINARY, *plast_propid);
	propval.pvalue = &tmp_bin;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_proposal(INT_HASH_TABLE *phash,
	uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	uint8_t tmp_byte;
	static uint32_t lid;
	TAGGED_PROPVAL propval;
	PROPERTY_NAME propname;
	
	/* PidLidAppointmentCounterProposal */
	lid = 0x00008257;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_BOOLEAN, *plast_propid);
	propval.pvalue = &tmp_byte;
	tmp_byte = 1;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_recipients(std::shared_ptr<ICAL_COMPONENT> pmain_event,
	USERNAME_TO_ENTRYID username_to_entryid, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	int address_type;
	uint8_t tmp_byte;
	const char *prole;
	const char *prsvp;
	uint32_t tmp_int32;
	TARRAY_SET *prcpts;
	uint8_t tmp_buff[1024];
	const char *pcutype;
	const char *paddress;
	TAGGED_PROPVAL propval;
	TPROPVAL_ARRAY *pproplist;
	const char *pdisplay_name;
	
	auto pmessage_class = static_cast<char *>(tpropval_array_get_propval(
	                      &pmsg->proplist, PROP_TAG_MESSAGECLASS));
	if (NULL == pmessage_class) {
		pmessage_class = static_cast<char *>(tpropval_array_get_propval(
		                 &pmsg->proplist, PROP_TAG_MESSAGECLASS_STRING8));
	}
	/* ignore ATTENDEE when METHOD is "PUBLIC" */
	if (NULL == pmessage_class || 0 == strcasecmp(
		pmessage_class, "IPM.Appointment")) {
		return TRUE;
	}
	prcpts = tarray_set_init();
	if (NULL == prcpts) {
		return FALSE;
	}
	tmp_byte = 0;
	message_content_set_rcpts_internal(pmsg, prcpts);
	for (auto piline : pmain_event->line_list) {
		if (strcasecmp(piline->name.c_str(), "ATTENDEE") != 0)
			continue;
		paddress = piline->get_first_subvalue();
		if (NULL == paddress || 0 != strncasecmp(paddress, "MAILTO:", 7)) {
			continue;
		}
		paddress += 7;
		pdisplay_name = piline->get_first_paramval("CN");
		pcutype = piline->get_first_paramval("CUTYPE");
		prole = piline->get_first_paramval("ROLE");
		prsvp = piline->get_first_paramval("RSVP");
		if (NULL != prsvp && 0 == strcasecmp(prsvp, "TRUE")) {
			tmp_byte = 1;
		}
		pproplist = tpropval_array_init();
		if (NULL == pproplist) {
			return FALSE;
		}
		if (!tarray_set_append_internal(prcpts, pproplist)) {
			tpropval_array_free(pproplist);
			return FALSE;
		}
		propval.proptag = PROP_TAG_ADDRESSTYPE;
		propval.pvalue  = deconst("SMTP");
		if (!tpropval_array_set_propval(pproplist, &propval))
			return FALSE;
		propval.proptag = PROP_TAG_EMAILADDRESS;
		propval.pvalue = deconst(paddress);
		if (!tpropval_array_set_propval(pproplist, &propval))
			return FALSE;
		propval.proptag = PROP_TAG_SMTPADDRESS;
		propval.pvalue = deconst(paddress);
		if (!tpropval_array_set_propval(pproplist, &propval))
			return FALSE;
		if (NULL == pdisplay_name) {
			pdisplay_name = paddress;
		}
		propval.proptag = PROP_TAG_DISPLAYNAME;
		propval.pvalue = deconst(pdisplay_name);
		if (!tpropval_array_set_propval(pproplist, &propval))
			return FALSE;
		propval.proptag = PROP_TAG_TRANSMITTABLEDISPLAYNAME;
		propval.pvalue = deconst(pdisplay_name);
		if (!tpropval_array_set_propval(pproplist, &propval))
			return FALSE;
		tmp_bin.pb = tmp_buff;
		tmp_bin.cb = 0;
		if (FALSE == username_to_entryid(paddress,
			pdisplay_name, &tmp_bin, &address_type)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_ENTRYID;
		propval.pvalue = &tmp_bin;
		if (!tpropval_array_set_propval(pproplist, &propval))
			return FALSE;
		propval.proptag = PROP_TAG_RECIPIENTENTRYID;
		propval.pvalue = &tmp_bin;
		if (!tpropval_array_set_propval(pproplist, &propval))
			return FALSE;
		propval.proptag = PROP_TAG_RECORDKEY;
		propval.pvalue = &tmp_bin;
		if (!tpropval_array_set_propval(pproplist, &propval))
			return FALSE;
		if (NULL != prole && 0 == strcasecmp(prole, "CHAIR")) {
			tmp_int32 = 1;
		} else if (NULL != prole && 0 == strcasecmp(
			prole, "REQ-PARTICIPANT")) {
			tmp_int32 = 1;
		} else if (NULL != prole && 0 == strcasecmp(
			prole, "OPT-PARTICIPANT")) {
			tmp_int32 = 2;
		} else if (NULL != pcutype && 0 == strcasecmp(
			pcutype, "RESOURCE")) {
			tmp_int32 = 3;
		} else if (NULL != pcutype && 0 == strcasecmp(
			pcutype, "ROOM")) {
			tmp_int32 = 3;
		} else if (NULL != prole && 0 == strcasecmp(
			prole, "NON-PARTICIPANT")) {
			tmp_int32 = 2;
		} else {
			tmp_int32 = 1;
		}
		propval.proptag = PROP_TAG_RECIPIENTTYPE;
		propval.pvalue = &tmp_int32;
		if (!tpropval_array_set_propval(pproplist, &propval))
			return FALSE;
		propval.proptag = PROP_TAG_OBJECTTYPE;
		propval.pvalue = &tmp_int32;
		if (ADDRESS_TYPE_MLIST == address_type) {
			tmp_int32 = OBJECT_DLIST;
		} else {
			tmp_int32 = OBJECT_USER;
		}
		if (!tpropval_array_set_propval(pproplist, &propval))
			return FALSE;
		propval.proptag = PROP_TAG_DISPLAYTYPE;
		propval.pvalue = &tmp_int32;
		switch (address_type) {
		case ADDRESS_TYPE_MLIST:
			tmp_int32 = DISPLAY_TYPE_DISTLIST;
			break;
		case ADDRESS_TYPE_ROOM:
			tmp_int32 = DISPLAY_TYPE_ROOM;
			break;
		case ADDRESS_TYPE_EQUIPMENT:
			tmp_int32 = DISPLAY_TYPE_EQUIPMENT;
			break;
		default:
			tmp_int32 = DISPLAY_TYPE_MAILUSER;
			break;
		}
		if (!tpropval_array_set_propval(pproplist, &propval))
			return FALSE;
		tmp_byte = 1;
		propval.proptag = PROP_TAG_RESPONSIBILITY;
		propval.pvalue = &tmp_byte;
		if (!tpropval_array_set_propval(pproplist, &propval))
			return FALSE;
		tmp_int32 = 1;
		propval.proptag = PROP_TAG_RECIPIENTFLAGS;
		propval.pvalue = &tmp_int32;
		if (!tpropval_array_set_propval(pproplist, &propval))
			return FALSE;
	}
	propval.proptag = PROP_TAG_RESPONSEREQUESTED;
	propval.pvalue = &tmp_byte;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	propval.proptag = PROP_TAG_REPLYREQUESTED;
	propval.pvalue = &tmp_byte;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	return TRUE;
}

static BOOL oxcical_parse_categories(std::shared_ptr<ICAL_LINE> piline,
	INT_HASH_TABLE *phash, uint16_t *plast_propid,
	MESSAGE_CONTENT *pmsg)
{
	char *tmp_buff[128];
	TAGGED_PROPVAL propval;
	PROPERTY_NAME propname;
	STRING_ARRAY strings_array;
	
	if (piline->value_list.size() == 0)
		return TRUE;
	auto pivalue = piline->value_list.front();
	strings_array.count = 0;
	strings_array.ppstr = tmp_buff;
	for (const auto &pnv2 : pivalue->subval_list) {
		if (!pnv2.has_value())
			continue;
		strings_array.ppstr[strings_array.count] = deconst(pnv2->c_str());
		strings_array.count ++;
		if (strings_array.count >= 128) {
			break;
		}
	}
	if (0 != strings_array.count && strings_array.count < 128) {
		/* PidNameKeywords */
		rop_util_get_common_pset(PS_PUBLIC_STRINGS, &propname.guid);
		propname.kind = MNID_STRING;
		propname.pname = deconst("Keywords");
		if (1 != int_hash_add(phash, *plast_propid, &propname)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG(PT_MV_UNICODE, *plast_propid);
		propval.pvalue = &strings_array;
		if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
			return FALSE;
		(*plast_propid) ++;
	}
	return TRUE;
}

static BOOL oxcical_parse_class(std::shared_ptr<ICAL_LINE> piline,
    MESSAGE_CONTENT *pmsg)
{
	uint32_t tmp_int32;
	const char *pvalue;
	TAGGED_PROPVAL propval;
	
	pvalue = piline->get_first_subvalue();
	if (NULL == pvalue) {
		return TRUE;
	}
	if (0 == strcasecmp(pvalue, "PERSONAL") ||
		0 == strcasecmp(pvalue, "X-PERSONAL")) {
		tmp_int32 = 1;
	} else if (0 == strcasecmp(pvalue, "PRIVATE")) {
		tmp_int32 = 2;
	} else if (0 == strcasecmp(pvalue, "CONFIDENTIAL")) {
		tmp_int32 = 3;
	} else if (0 == strcasecmp(pvalue, "PUBLIC")) {
		tmp_int32 = 0;
	} else {
		return TRUE;
	}
	propval.proptag = PROP_TAG_SENSITIVITY;
	propval.pvalue = &tmp_int32;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	return TRUE;
}

static BOOL oxcical_parse_body(std::shared_ptr<ICAL_LINE> piline,
    MESSAGE_CONTENT *pmsg)
{
	const char *pvalue;
	TAGGED_PROPVAL propval;
	
	pvalue = piline->get_first_subvalue();
	if (NULL == pvalue) {
		return TRUE;
	}
	propval.proptag = PROP_TAG_BODY;
	propval.pvalue = deconst(pvalue);
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	return TRUE;
}

static BOOL oxcical_parse_html(std::shared_ptr<ICAL_LINE> piline,
    MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	const char *pvalue;
	uint32_t tmp_int32;
	TAGGED_PROPVAL propval;
	
	pvalue = piline->get_first_subvalue();
	if (NULL == pvalue) {
		return TRUE;
	}
	propval.proptag = PROP_TAG_HTML;
	propval.pvalue = &tmp_bin;
	tmp_bin.cb = strlen(pvalue);
	tmp_bin.pc = deconst(pvalue);
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	propval.proptag = PROP_TAG_INTERNETCODEPAGE;
	propval.pvalue = &tmp_int32;
	tmp_int32 = 65001;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	return TRUE;
}

static BOOL oxcical_parse_dtstamp(std::shared_ptr<ICAL_LINE> piline,
	const char *method, INT_HASH_TABLE *phash,
	uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	time_t tmp_time;
	uint64_t tmp_int64;
	const char *pvalue;
	static uint32_t lid1;
	static uint32_t lid2;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	pvalue = piline->get_first_subvalue();
	if (NULL == pvalue) {
		return TRUE;
	}
	if (!ical_datetime_to_utc(nullptr, pvalue, &tmp_time))
		return TRUE;
	if (method != nullptr && (strcasecmp(method, "REPLY") == 0 ||
	    strcasecmp(method, "COUNTER") == 0)) {
		/* PidLidAttendeeCriticalChange */
		lid1 = 0x00000001;
		propname.plid = &lid1;
	} else {
		/* PidLidOwnerCriticalChange */
		lid2 = 0x0000001A;
		propname.plid = &lid2;
	}
	propname.kind = MNID_ID;
	rop_util_get_common_pset(PSETID_MEETING, &propname.guid);
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_SYSTIME, *plast_propid);
	propval.pvalue = &tmp_int64;
	tmp_int64 = rop_util_unix_to_nttime(tmp_time);
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_start_end(BOOL b_start, BOOL b_proposal,
    std::shared_ptr<ICAL_COMPONENT> pmain_event, time_t unix_time,
    INT_HASH_TABLE *phash, uint16_t *plast_propid,  MESSAGE_CONTENT *pmsg)
{
	uint64_t tmp_int64;
	static uint32_t lid1;
	static uint32_t lid2;
	static uint32_t lid3;
	static uint32_t lid4;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	tmp_int64 = rop_util_unix_to_nttime(unix_time);
	if (TRUE == b_proposal) {
		if (TRUE == b_start) {
			/* PidLidAppointmentProposedStartWhole */
			lid1 = 0x00008250;
			propname.plid = &lid1;
		} else {
			/* PidLidAppointmentProposedEndWhole */
			lid2 = 0x00008251;
			propname.plid = &lid2;
		}
		propname.kind = MNID_ID;
		rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
		if (1 != int_hash_add(phash, *plast_propid, &propname)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG(PT_SYSTIME, *plast_propid);
		propval.pvalue = &tmp_int64;
		if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
			return FALSE;
		(*plast_propid) ++;
	}
	if (FALSE == b_proposal ||
	    (pmain_event->get_line("X-MS-OLK-ORIGINALEND") == nullptr &&
	    pmain_event->get_line("X-MS-OLK-ORIGINALSTART") == nullptr)) {
		if (TRUE == b_start) {
			/* PidLidAppointmentStartWhole */
			lid3 = 0x0000820D;
			propname.plid = &lid3;
		} else {
			/* PidLidAppointmentEndWhole */
			lid4 = 0x0000820E;
			propname.plid = &lid4;
		}
		propname.kind = MNID_ID;
		rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
		if (1 != int_hash_add(phash, *plast_propid, &propname)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG(PT_SYSTIME, *plast_propid);
		propval.pvalue = &tmp_int64;
		if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
			return FALSE;
		(*plast_propid) ++;
	}
	return TRUE;
}

static BOOL oxcical_parse_subtype(INT_HASH_TABLE *phash,
	uint16_t *plast_propid, MESSAGE_CONTENT *pmsg,
	EXCEPTIONINFO *pexception)
{
	uint8_t tmp_byte;
	static uint32_t lid;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	/* PidLidAppointmentSubType */
	lid = 0x00008215;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_BOOLEAN, *plast_propid);
	propval.pvalue = &tmp_byte;
	tmp_byte = 1;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	if (NULL != pexception) {
		pexception->overrideflags |= OVERRIDEFLAG_SUBTYPE;
		pexception->subtype = 1;
	}
	return TRUE;
}

static BOOL oxcical_parse_dates(std::shared_ptr<ICAL_COMPONENT> ptz_component,
    std::shared_ptr<ICAL_LINE> piline, uint32_t *pcount, uint32_t *pdates)
{
	int i;
	bool b_utc;
	ICAL_TIME itime;
	time_t tmp_time;
	uint32_t tmp_date;
	const char *pvalue;
	
	if (piline->value_list.size() == 0)
		return TRUE;
	*pcount = 0;
	auto pivalue = piline->value_list.front();
	pvalue = piline->get_first_paramval("VALUE");
	if (NULL == pvalue || 0 == strcasecmp(pvalue, "DATE-TIME")) {
		for (const auto &pnv2 : pivalue->subval_list) {
			if (!pnv2.has_value())
				continue;
			if (!ical_parse_datetime(pnv2->c_str(), &b_utc, &itime))
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
			for (i=0; i<*pcount; i++) {
				if (tmp_date == pdates[i]) {
					return TRUE;
				}
			}
			pdates[*pcount] = tmp_date;
			(*pcount) ++;
			if (*pcount >= 1024) {
				return TRUE;
			}
		}
	} else if (0 == strcasecmp(pvalue, "DATE")) {
		for (const auto &pnv2 : pivalue->subval_list) {
			if (!pnv2.has_value())
				continue;
			memset(&itime, 0, sizeof(ICAL_TIME));
			if (!ical_parse_date(pnv2->c_str(), &itime.year, &itime.month, &itime.day))
				continue;
			ical_itime_to_utc(NULL, itime, &tmp_time);
			pdates[*pcount] = rop_util_unix_to_nttime(tmp_time)/600000000;
			(*pcount) ++;
			if (*pcount >= 1024) {
				return TRUE;
			}
		}
	} else {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_parse_duration(uint32_t minutes,
	INT_HASH_TABLE *phash, uint16_t *plast_propid,
	MESSAGE_CONTENT *pmsg)
{
	static uint32_t lid;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	/* PidLidAppointmentDuration  */
	lid = 0x00008213;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_LONG, *plast_propid);
	propval.pvalue = &minutes;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_dtvalue(std::shared_ptr<ICAL_COMPONENT> ptz_component,
    std::shared_ptr<ICAL_LINE> piline, bool *b_utc, ICAL_TIME *pitime,
    time_t *putc_time)
{
	const char *pvalue;
	const char *pvalue1;
	
	pvalue = piline->get_first_subvalue();
	if (NULL == pvalue) {
		return FALSE;
	}
	pvalue1 = piline->get_first_paramval("VALUE");
	if (NULL == pvalue1 || 0 == strcasecmp(pvalue1, "DATE-TIME")) {
		if (!ical_parse_datetime(pvalue, b_utc, pitime)) {
			if (NULL == pvalue1) {
				goto PARSE_DATE_VALUE;
			}
			return FALSE;
		}
		if (*b_utc) {
			if (!ical_itime_to_utc(nullptr, *pitime, putc_time))
				return FALSE;
		} else {
			if (!ical_itime_to_utc(ptz_component, *pitime, putc_time))
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

static BOOL oxcical_parse_uid(std::shared_ptr<ICAL_LINE> piline,
	ICAL_TIME effective_itime, EXT_BUFFER_ALLOC alloc,
	INT_HASH_TABLE *phash, uint16_t *plast_propid,
	MESSAGE_CONTENT *pmsg)
{
	int tmp_len;
	BINARY tmp_bin;
	EXT_PULL ext_pull;
	EXT_PUSH ext_push;
	const char *pvalue;
	char tmp_buff[1024];
	static uint32_t lid;
	static uint32_t lid1;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	GLOBALOBJECTID globalobjectid;
	
	pvalue = piline->get_first_subvalue();
	if (NULL == pvalue) {
		return TRUE;
	}
	tmp_len = strlen(pvalue);
	if (strncasecmp(pvalue, EncodedGlobalId_hex, 32) == 0) {
		if (TRUE == decode_hex_binary(pvalue, tmp_buff, 1024)) {
			ext_buffer_pull_init(&ext_pull, tmp_buff, tmp_len/2, alloc, 0);
			if (EXT_ERR_SUCCESS == ext_buffer_pull_globalobjectid(
				&ext_pull, &globalobjectid) && ext_pull.offset == tmp_len/2) {
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
	}
	memset(&globalobjectid, 0, sizeof(GLOBALOBJECTID));
	memcpy(globalobjectid.arrayid, EncodedGlobalId, 16);
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
	ext_buffer_push_init(&ext_push, tmp_buff, 1024, 0);
	if (EXT_ERR_SUCCESS != ext_buffer_push_globalobjectid(
		&ext_push, &globalobjectid)) {
		return FALSE;
	}
	tmp_bin.cb = ext_push.offset;
	tmp_bin.pc = tmp_buff;
	/* PidLidGlobalObjectId */
	lid = 0x00000003;
	rop_util_get_common_pset(PSETID_MEETING, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_BINARY, *plast_propid);
	propval.pvalue = &tmp_bin;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	globalobjectid.year = 0;
	globalobjectid.month = 0;
	globalobjectid.day = 0;
	ext_buffer_push_init(&ext_push, tmp_buff, 1024, 0);
	if (EXT_ERR_SUCCESS != ext_buffer_push_globalobjectid(
		&ext_push, &globalobjectid)) {
		return FALSE;
	}
	tmp_bin.cb = ext_push.offset;
	tmp_bin.pc = tmp_buff;
	/* PidLidCleanGlobalObjectId */
	lid1 = 0x00000023;
	rop_util_get_common_pset(PSETID_MEETING, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid1;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_BINARY, *plast_propid);
	propval.pvalue = &tmp_bin;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_location(std::shared_ptr<ICAL_LINE> piline,
    INT_HASH_TABLE *phash, uint16_t *plast_propid, EXT_BUFFER_ALLOC alloc,
	MESSAGE_CONTENT *pmsg, EXCEPTIONINFO *pexception,
	EXTENDEDEXCEPTION *pext_exception)
{
	int i;
	int tmp_len;
	const char *pvalue;
	char tmp_buff[1024];
	static uint32_t lid;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	pvalue = piline->get_first_subvalue();
	if (NULL == pvalue) {
		return TRUE;
	}
	tmp_len = strlen(pvalue);
	if (tmp_len >= 1024) {
		return TRUE;
	}
	memcpy(tmp_buff, pvalue, tmp_len + 1);
	if (FALSE == utf8_truncate(tmp_buff, 255)) {
		return TRUE;
	}
	tmp_len = strlen(tmp_buff);
	for (i=0; i<tmp_len; i++) {
		if ('\r' == tmp_buff[i] || '\n' == tmp_buff[i]) {
			memmove(tmp_buff + i, tmp_buff + i + 1, tmp_len - i);
			tmp_len --;
		}
	}
	/* PidLidLocation */
	lid = 0x00008208;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_UNICODE, *plast_propid);
	propval.pvalue = tmp_buff;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	pvalue = piline->get_first_paramval("ALTREP");
	if (NULL == pvalue) {
		return TRUE;
	}
	/* PidNameLocationUrl */
	rop_util_get_common_pset(PS_PUBLIC_STRINGS, &propname.guid);
	propname.kind = MNID_STRING;
	propname.pname = deconst("urn:schemas:calendar:locationurl");
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_UNICODE, *plast_propid);
	propval.pvalue = deconst(pvalue);
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	if (NULL != pexception && NULL != pext_exception) {
		pexception->overrideflags |= OVERRIDEFLAG_LOCATION;
		pexception->location = static_cast<char *>(alloc(tmp_len + 1));
		if (NULL == pexception->location) {
			return FALSE;
		}
		strcpy(pexception->location, tmp_buff);
		pext_exception->location = static_cast<char *>(alloc(tmp_len + 1));
		if (NULL == pext_exception->location) {
			return FALSE;
		}
		strcpy(pext_exception->location, tmp_buff);
	}
	return TRUE;
}

static BOOL oxcical_parse_organizer(std::shared_ptr<ICAL_LINE> piline,
	USERNAME_TO_ENTRYID username_to_entryid, MESSAGE_CONTENT *pmsg)
{
	void *pvalue;
	BINARY tmp_bin;
	uint8_t tmp_buff[1024];
	const char *paddress;
	TAGGED_PROPVAL propval;
	const char *pdisplay_name;
	
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_MESSAGECLASS);
	if (NULL == pvalue) {
		pvalue = tpropval_array_get_propval(
			&pmsg->proplist, PROP_TAG_MESSAGECLASS_STRING8);
	}
	if (NULL == pvalue) {
		return FALSE;
	}
	/* ignore ORGANIZER when METHOD is "REPLY" OR "COUNTER" */
	if (strncasecmp(static_cast<char *>(pvalue), "IPM.Schedule.Meeting.Resp.", 26) == 0)
		return TRUE;
	paddress = piline->get_first_subvalue();
	if (NULL != paddress) {
		if (0 == strncasecmp(paddress, "MAILTO:", 7)) {
			paddress += 7;
		} else {
			paddress = NULL;
		}
	}
	pdisplay_name = piline->get_first_paramval("CN");
	if (NULL != pdisplay_name) {
		propval.proptag = PROP_TAG_SENTREPRESENTINGNAME;
		propval.pvalue = deconst(pdisplay_name);
		if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
			return FALSE;
		propval.proptag = PROP_TAG_SENDERNAME;
		propval.pvalue = deconst(pdisplay_name);
		if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
			return FALSE;
	}
	if (NULL == paddress) {
		return TRUE;
	}
	tmp_bin.pb = tmp_buff;
	tmp_bin.cb = 0;
	if (FALSE == username_to_entryid(paddress,
		pdisplay_name, &tmp_bin, NULL)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_SENTREPRESENTINGADDRESSTYPE;
	propval.pvalue  = deconst("SMTP");
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	propval.proptag = PROP_TAG_SENTREPRESENTINGEMAILADDRESS;
	propval.pvalue = deconst(paddress);
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	propval.proptag = PROP_TAG_SENTREPRESENTINGSMTPADDRESS;
	propval.pvalue = deconst(paddress);
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	propval.proptag = PROP_TAG_SENTREPRESENTINGENTRYID;
	propval.pvalue = &tmp_bin;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	propval.proptag = PROP_TAG_SENDERADDRESSTYPE;
	propval.pvalue  = deconst("SMTP");
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	propval.proptag = PROP_TAG_SENDEREMAILADDRESS;
	propval.pvalue = deconst(paddress);
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	propval.proptag = PROP_TAG_SENDERSMTPADDRESS;
	propval.pvalue = deconst(paddress);
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	propval.proptag = PROP_TAG_SENDERENTRYID;
	propval.pvalue = &tmp_bin;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	return TRUE;
}

static BOOL oxcical_parse_sequence(std::shared_ptr<ICAL_LINE> piline,
	INT_HASH_TABLE *phash, uint16_t *plast_propid,
	MESSAGE_CONTENT *pmsg)
{
	uint32_t tmp_int32;
	const char *pvalue;
	static uint32_t lid;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	pvalue = piline->get_first_subvalue();
	if (NULL == pvalue) {
		return TRUE;
	}
	tmp_int32 = atoi(pvalue);
	/* PidLidAppointmentSequence */
	lid = 0x00008201;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_LONG, *plast_propid);
	propval.pvalue = &tmp_int32;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_busystatus(std::shared_ptr<ICAL_LINE> piline,
	uint32_t intented_val, INT_HASH_TABLE *phash,
	uint16_t *plast_propid, MESSAGE_CONTENT *pmsg,
	EXCEPTIONINFO *pexception)
{
	uint32_t tmp_int32;
	const char *pvalue;
	static uint32_t lid;
	static uint32_t lid1;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	pvalue = piline->get_first_subvalue();
	if (NULL == pvalue) {
		return TRUE;
	}
	if (0 == strcasecmp(pvalue, "FREE")) {
		tmp_int32 = 0;
	} else if (0 == strcasecmp(pvalue, "TENTATIVE")) {
		tmp_int32 = 1;
	} else if (0 == strcasecmp(pvalue, "BUSY")) {
		tmp_int32 = 2;
	} else if (0 == strcasecmp(pvalue, "OOF")) {
		tmp_int32 = 3;
	} else {
		return TRUE;
	}
	/* PidLidBusyStatus */
	lid = 0x00008205;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_LONG, *plast_propid);
	propval.pvalue = &tmp_int32;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	if (NULL != pexception) {
		pexception->overrideflags |= OVERRIDEFLAG_BUSYSTATUS;
		pexception->busystatus = tmp_int32;
	}
	if (0 == intented_val) {
		return TRUE;
	} else if (2 == intented_val) {
		intented_val = tmp_int32;
	}
	/* PidLidIntendedBusyStatus */
	lid1 = 0x00008224;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid1;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_LONG, *plast_propid);
	propval.pvalue = &intented_val;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_transp(std::shared_ptr<ICAL_LINE> piline,
	uint32_t intented_val, INT_HASH_TABLE *phash,
	uint16_t *plast_propid, MESSAGE_CONTENT *pmsg,
	EXCEPTIONINFO *pexception)
{
	uint32_t tmp_int32;
	const char *pvalue;
	static uint32_t lid;
	static uint32_t lid1;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	pvalue = piline->get_first_subvalue();
	if (NULL == pvalue) {
		return TRUE;
	}
	if (0 == strcasecmp(pvalue, "TRANSPARENT")) {
		tmp_int32 = 0;
	} else if (0 == strcasecmp(pvalue, "OPAQUE")) {
		tmp_int32 = 2;
	} else {
		return TRUE;
	}
	/* PidLidBusyStatus */
	lid = 0x00008205;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_LONG, *plast_propid);
	propval.pvalue = &tmp_int32;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	if (NULL != pexception) {
		pexception->overrideflags |= OVERRIDEFLAG_BUSYSTATUS;
		pexception->busystatus = tmp_int32;
	}
	if (0 == intented_val) {
		return TRUE;
	} else if (2 == intented_val) {
		intented_val = tmp_int32;
	}
	/* PidLidIntendedBusyStatus */
	lid1 = 0x00008224;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid1;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_LONG, *plast_propid);
	propval.pvalue = &intented_val;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_status(std::shared_ptr<ICAL_LINE> piline,
	uint32_t intented_val, INT_HASH_TABLE *phash,
	uint16_t *plast_propid, MESSAGE_CONTENT *pmsg,
	EXCEPTIONINFO *pexception)
{
	uint32_t tmp_int32;
	const char *pvalue;
	static uint32_t lid;
	static uint32_t lid1;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	pvalue = piline->get_first_subvalue();
	if (NULL == pvalue) {
		return TRUE;
	}
	if (0 == strcasecmp(pvalue, "CANCELLED")) {
		tmp_int32 = 0;
	} else if (0 == strcasecmp(pvalue, "TENTATIVE")) {
		tmp_int32 = 1;
	}  else if (0 == strcasecmp(pvalue, "CONFIRMED")) {
		tmp_int32 = 2;
	} else {
		return TRUE;
	}
	/* PidLidBusyStatus */
	lid = 0x00008205;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_LONG, *plast_propid);
	propval.pvalue = &tmp_int32;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	if (NULL != pexception) {
		pexception->overrideflags |= OVERRIDEFLAG_BUSYSTATUS;
		pexception->busystatus = tmp_int32;
	}
	if (0 == intented_val) {
		return TRUE;
	} else if (2 == intented_val) {
		intented_val = tmp_int32;
	}
	/* PidLidIntendedBusyStatus */
	lid1 = 0x00008224;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid1;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_LONG, *plast_propid);
	propval.pvalue = &intented_val;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_summary(
    std::shared_ptr<ICAL_LINE> piline, MESSAGE_CONTENT *pmsg,
	EXT_BUFFER_ALLOC alloc, EXCEPTIONINFO *pexception,
	EXTENDEDEXCEPTION *pext_exception)
{
	int i;
	int tmp_len;
	const char *pvalue;
	char tmp_buff[1024];
	TAGGED_PROPVAL propval;
	
	pvalue = piline->get_first_subvalue();
	if (NULL == pvalue) {
		return TRUE;
	}
	tmp_len = strlen(pvalue);
	if (tmp_len >= 1024) {
		return TRUE;
	}
	memcpy(tmp_buff, pvalue, tmp_len + 1);
	if (FALSE == utf8_truncate(tmp_buff, 255)) {
		return TRUE;
	}
	tmp_len = strlen(tmp_buff);
	for (i=0; i<tmp_len; i++) {
		if ('\r' == tmp_buff[i] || '\n' == tmp_buff[i]) {
			memmove(tmp_buff + i, tmp_buff + i + 1, tmp_len - i);
			tmp_len --;
		}
	}
	propval.proptag = PROP_TAG_SUBJECT;
	propval.pvalue = tmp_buff;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	if (NULL != pexception && NULL != pext_exception) {
		pexception->overrideflags |= OVERRIDEFLAG_SUBJECT;
		pexception->subject = static_cast<char *>(alloc(tmp_len + 1));
		if (NULL == pexception->subject) {
			return FALSE;
		}
		strcpy(pexception->subject, tmp_buff);
		pext_exception->subject = static_cast<char *>(alloc(tmp_len + 1));
		if (NULL == pext_exception->subject) {
			return FALSE;
		}
		strcpy(pext_exception->subject, tmp_buff);
	}
	return TRUE;
}

static BOOL oxcical_parse_ownerapptid(std::shared_ptr<ICAL_LINE> piline,
    MESSAGE_CONTENT *pmsg)
{
	uint32_t tmp_int32;
	const char *pvalue;
	TAGGED_PROPVAL propval;
	
	pvalue = piline->get_first_subvalue();
	if (NULL == pvalue) {
		return TRUE;
	}
	tmp_int32 = atoi(pvalue);
	propval.proptag = PROP_TAG_OWNERAPPOINTMENTID;
	propval.pvalue = &tmp_int32;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	return TRUE;
}

static BOOL oxcical_parse_recurrence_id(std::shared_ptr<ICAL_COMPONENT> ptz_component,
    std::shared_ptr<ICAL_LINE> piline, INT_HASH_TABLE *phash,
    uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	time_t tmp_time;
	ICAL_TIME itime;
	uint64_t tmp_int64;
	static uint32_t lid;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	bool b_utc;
	
	if (FALSE == oxcical_parse_dtvalue(ptz_component,
		piline, &b_utc, &itime, &tmp_time)) {
		return FALSE;
	}
	/* PidLidExceptionReplaceTime */
	lid = 0x00008228;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_SYSTIME, *plast_propid);
	propval.pvalue = &tmp_int64;
	tmp_int64 = rop_util_unix_to_nttime(tmp_time);
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_disallow_counter(std::shared_ptr<ICAL_LINE> piline,
	INT_HASH_TABLE *phash, uint16_t *plast_propid,
	MESSAGE_CONTENT *pmsg)
{
	uint8_t tmp_byte;
	const char *pvalue;
	static uint32_t lid;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	pvalue = piline->get_first_subvalue();
	if (NULL == pvalue) {
		return TRUE;
	}
	if (0 == strcasecmp(pvalue, "TRUE")) {
		tmp_byte = 1;
	} else if (0 == strcasecmp(pvalue, "FALSE")) {
		tmp_byte = 0;
	} else {
		return TRUE;
	}
	/* PidLidAppointmentNotAllowPropose */
	lid = 0x0000825A;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_BOOLEAN, *plast_propid);
	propval.pvalue = &tmp_byte;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static int oxcical_cmp_date(const void *pdate1, const void *pdate2)
{
	auto a = *static_cast<const uint32_t *>(pdate1);
	auto b = *static_cast<const uint32_t *>(pdate2);
	return a == b ? 0 : a < b ? -1 : 1;
}

static BOOL oxcical_parse_appointment_recurrence(
	APPOINTMENTRECURRENCEPATTERN *papprecurr,
	INT_HASH_TABLE *phash, uint16_t *plast_propid,
	MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	uint64_t nt_time;
	EXT_PUSH ext_push;
	static uint32_t lid1;
	static uint32_t lid2;
	static uint32_t lid3;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	if (FALSE == ext_buffer_push_init(&ext_push, NULL, 0, EXT_FLAG_UTF16)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_appointmentrecurrencepattern(
		&ext_push, papprecurr)) {
		ext_buffer_push_free(&ext_push);
		return FALSE;
	}
	tmp_bin.cb = ext_push.offset;
	tmp_bin.pb = ext_push.data;
	/* PidLidAppointmentRecur */
	lid1 = 0x00008216;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid1;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		ext_buffer_push_free(&ext_push);
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_BINARY, *plast_propid);
	propval.pvalue = &tmp_bin;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		ext_buffer_push_free(&ext_push);
		return FALSE;
	}
	ext_buffer_push_free(&ext_push);
	(*plast_propid) ++;
	if (ENDTYPE_NEVER_END == papprecurr->recurrencepattern.endtype ||
		ENDTYPE_NEVER_END1 == papprecurr->recurrencepattern.endtype) {
		/* 31 August 4500, 11:59 P.M */
		nt_time = 1525076159;
	} else {
		nt_time = papprecurr->recurrencepattern.enddate;
	}
	nt_time *= 600000000;
	/* PidLidClipEnd */
	lid2 = 0x00008236;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid2;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_SYSTIME, *plast_propid);
	propval.pvalue = &nt_time;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	nt_time = papprecurr->recurrencepattern.startdate;
	nt_time *= 600000000;
	/* PidLidClipStart */
	lid3 = 0x00008235;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid3;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_SYSTIME, *plast_propid);
	propval.pvalue = &nt_time;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static int oxcical_cmp_exception(
	const void *pexception1, const void *pexception2)
{
	auto a = static_cast<const EXCEPTIONINFO *>(pexception1);
	auto b = static_cast<const EXCEPTIONINFO *>(pexception2);
	return a->startdatetime == b->startdatetime ? 0 :
	       a->startdatetime < b->startdatetime ? -1 : 1;
}

static int oxcical_cmp_ext_exception(
	const void *pext_exception1, const void *pext_exception2)
{
	auto a = static_cast<const EXTENDEDEXCEPTION *>(pext_exception1);
	auto b = static_cast<const EXTENDEDEXCEPTION *>(pext_exception2);
	return a->startdatetime == b->startdatetime ? 0 :
	       a->startdatetime < b->startdatetime ? -1 : 1;
}

static void oxcical_replace_propid(
	TPROPVAL_ARRAY *pproplist, INT_HASH_TABLE *phash)
{
	int i;
	uint16_t propid;
	uint32_t proptag;
	uint16_t *ppropid;
	
	for (i=0; i<pproplist->count; i++) {
		proptag = pproplist->ppropval[i].proptag;
		propid = PROP_ID(proptag);
		if (0 == (propid & 0x8000)) {
			continue;
		}
		ppropid = static_cast<uint16_t *>(int_hash_query(phash, propid));
		if (NULL == ppropid || 0 == *ppropid) {
			tpropval_array_remove_propval(pproplist, proptag);
			i --;
			continue;
		}
		pproplist->ppropval[i].proptag =
			PROP_TAG(PROP_TYPE(pproplist->ppropval[i].proptag), *ppropid);
	}
}

static BOOL oxcical_fetch_propname(MESSAGE_CONTENT *pmsg,
	INT_HASH_TABLE *phash, EXT_BUFFER_ALLOC alloc,
	GET_PROPIDS get_propids)
{
	int i, tmp_int;
	INT_HASH_ITER *iter;
	PROPID_ARRAY propids;
	PROPID_ARRAY propids1;
	PROPERTY_NAME *ppropname;
	PROPNAME_ARRAY propnames;
	
	propids.count = 0;
	propids.ppropid = static_cast<uint16_t *>(alloc(sizeof(uint16_t) * phash->item_num));
	if (NULL == propids.ppropid) {
		return FALSE;
	}
	propnames.count = 0;
	propnames.ppropname = static_cast<PROPERTY_NAME *>(alloc(sizeof(PROPERTY_NAME) * phash->item_num));
	if (NULL == propnames.ppropname) {
		return FALSE;
	}
	iter = int_hash_iter_init(phash);
	for (int_hash_iter_begin(iter); !int_hash_iter_done(iter);
		int_hash_iter_forward(iter)) {
		ppropname = static_cast<PROPERTY_NAME *>(int_hash_iter_get_value(iter, &tmp_int));
		propids.ppropid[propids.count] = tmp_int;
		propnames.ppropname[propnames.count] = *ppropname;
		propids.count ++;
		propnames.count ++;
	}
	int_hash_iter_free(iter);
	if (FALSE == get_propids(&propnames, &propids1)) {
		return FALSE;
	}
	INT_HASH_TABLE *phash1 = int_hash_init(0x1000, sizeof(uint16_t));
	if (NULL == phash1) {
		return FALSE;
	}
	for (i=0; i<propids.count; i++) {
		int_hash_add(phash1, propids.ppropid[i], propids1.ppropid + i);
	}
	oxcical_replace_propid(&pmsg->proplist, phash1);
	if (NULL != pmsg->children.prcpts) {
		for (i=0; i<pmsg->children.prcpts->count; i++) {
			oxcical_replace_propid(pmsg->children.prcpts->pparray[i], phash1);
		}
	}
	if (NULL != pmsg->children.pattachments) {
		for (i=0; i<pmsg->children.pattachments->count; i++) {
			oxcical_replace_propid(
				&pmsg->children.pattachments->pplist[i]->proplist, phash1);
		}
	}
	int_hash_free(phash1);
	return TRUE;
}

static BOOL oxcical_parse_exceptional_attachment(ATTACHMENT_CONTENT *pattachment,
    std::shared_ptr<ICAL_COMPONENT> pcomponent, ICAL_TIME start_itime,
    ICAL_TIME end_itime, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	time_t tmp_time;
	uint8_t tmp_byte;
	uint32_t tmp_int32;
	uint64_t tmp_int64;
	TAGGED_PROPVAL propval;
	
	propval.proptag = PROP_TAG_ATTACHMETHOD;
	propval.pvalue = &tmp_int32;
	tmp_int32 = ATTACH_METHOD_EMBEDDED;
	if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
		return FALSE;
	propval.proptag = PROP_TAG_RENDERINGPOSITION;
	propval.pvalue = &tmp_int32;
	tmp_int32 = 0xFFFFFFFF;
	if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
		return FALSE;
	propval.proptag = PROP_TAG_DISPLAYNAME;
	propval.pvalue = tpropval_array_get_propval(
		&pattachment->pembedded->proplist, PROP_TAG_SUBJECT);
	if (NULL != propval.pvalue) {
		if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
			return FALSE;
	}
	if (!ical_itime_to_utc(nullptr, start_itime, &tmp_time))
		return FALSE;
	propval.proptag = PROP_TAG_EXCEPTIONSTARTTIME;
	propval.pvalue = &tmp_int64;
	tmp_int64 = rop_util_unix_to_nttime(tmp_time);
	if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
		return FALSE;
	if (!ical_itime_to_utc(nullptr, end_itime, &tmp_time))
		return FALSE;
	propval.proptag = PROP_TAG_EXCEPTIONENDTIME;
	propval.pvalue = &tmp_int64;
	tmp_int64 = rop_util_unix_to_nttime(tmp_time);
	if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
		return FALSE;
	propval.proptag = PROP_TAG_ATTACHENCODING;
	propval.pvalue = &tmp_bin;
	tmp_bin.cb = 0;
	tmp_bin.pb = NULL;
	if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
		return FALSE;
	propval.proptag = PROP_TAG_ATTACHMENTFLAGS;
	propval.pvalue = &tmp_int32;
	tmp_int32 = 0x00000002;
	if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
		return FALSE;
	propval.proptag = PROP_TAG_ATTACHMENTLINKID;
	propval.pvalue = &tmp_int32;
	tmp_int32 = 0x00000000;
	if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
		return FALSE;
	propval.proptag = PROP_TAG_ATTACHFLAGS;
	propval.pvalue = &tmp_int32;
	tmp_int32 = 0x00000000;
	if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
		return FALSE;
	propval.proptag = PROP_TAG_ATTACHMENTHIDDEN;
	propval.pvalue = &tmp_byte;
	tmp_byte = 1;
	if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
		return FALSE;
	propval.proptag = PROP_TAG_ATTACHMENTCONTACTPHOTO;
	propval.pvalue = &tmp_byte;
	tmp_byte = 0;
	if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
		return FALSE;
	return TRUE;
}

static BOOL oxcical_parse_attachment(std::shared_ptr<ICAL_LINE> piline,
    int count, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	uint8_t tmp_byte;
	size_t decode_len;
	uint32_t tmp_int32;
	uint64_t tmp_int64;
	const char *pvalue;
	const char *pvalue1;
	char tmp_buff[1024];
	TAGGED_PROPVAL propval;
	ATTACHMENT_LIST *pattachments;
	ATTACHMENT_CONTENT *pattachment;
	
	pvalue = piline->get_first_paramval("VALUE");
	if (NULL == pvalue) {
		pvalue = piline->get_first_subvalue();
		if (NULL != pvalue && 0 != strncasecmp(pvalue, "CID:", 4)) {
			if (NULL == pmsg->children.pattachments) {
				pattachments = attachment_list_init();
				if (NULL == pattachments) {
					return FALSE;
				}
				message_content_set_attachments_internal(
					pmsg, pattachments);
			} else {
				pattachments = pmsg->children.pattachments;
			}
			pattachment = attachment_content_init();
			if (NULL == pattachment) {
				return FALSE;
			}
			if (FALSE == attachment_list_append_internal(
				pattachments, pattachment)) {
				attachment_content_free(pattachment);
				return FALSE;
			}
			tmp_bin.cb = gx_snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff),
				"[InternetShortcut]\r\nURL=%s", pvalue);
			tmp_bin.pc = tmp_buff;
			propval.proptag = PROP_TAG_ATTACHDATABINARY;
			propval.pvalue = &tmp_bin;
			if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
				return FALSE;
			propval.proptag = PROP_TAG_ATTACHENCODING;
			propval.pvalue = &tmp_bin;
			tmp_bin.cb = 0;
			tmp_bin.pb = NULL;
			if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
				return FALSE;
			propval.proptag = PROP_TAG_ATTACHEXTENSION;
			propval.pvalue  = deconst(".URL");
			if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
				return FALSE;
			pvalue1 = strrchr(pvalue, '/');
			if (NULL == pvalue1) {
				pvalue1 = pvalue;
			}
			snprintf(tmp_buff, 256, "%s.url", pvalue1);
			propval.proptag = PROP_TAG_ATTACHLONGFILENAME;
			propval.pvalue = tmp_buff;
			if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
				return FALSE;
			propval.proptag = PROP_TAG_DISPLAYNAME;
			if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
				return FALSE;
			propval.proptag = PROP_TAG_ATTACHMETHOD;
			propval.pvalue = &tmp_int32;
			tmp_int32 = ATTACH_METHOD_BY_VALUE;
			pvalue1 = piline->get_first_paramval("FMTYPE");
			if (NULL != pvalue1) {
				propval.proptag = PROP_TAG_ATTACHMIMETAG;
				propval.pvalue = deconst(pvalue1);
				if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
					return FALSE;
			}
			propval.proptag = PROP_TAG_ATTACHFLAGS;
			propval.pvalue = &tmp_int32;
			tmp_int32 = 0;
			if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
				return FALSE;
			propval.proptag = PROP_TAG_ATTACHMENTLINKID;
			propval.pvalue = &tmp_int32;
			tmp_int32 = 0;
			if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
				return FALSE;
			propval.proptag = PROP_TAG_ATTACHMENTCONTACTPHOTO;
			propval.pvalue = &tmp_byte;
			tmp_byte = 0;
			if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
				return FALSE;
			propval.proptag = PROP_TAG_ATTACHMENTCONTACTPHOTO;
			propval.pvalue = &tmp_byte;
			tmp_byte = 0;
			if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
				return FALSE;
			propval.proptag = PROP_TAG_EXCEPTIONSTARTTIME;
			propval.pvalue = &tmp_int64;
			tmp_int64 = 0x0CB34557A3DD4000;
			if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
				return FALSE;
			propval.proptag = PROP_TAG_EXCEPTIONENDTIME;
			if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
				return FALSE;
			propval.proptag = PROP_TAG_RENDERINGPOSITION;
			propval.pvalue = &tmp_int32;
			tmp_int32 = 0xFFFFFFFF;
			if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
				return FALSE;
		}
	} else if (0 == strcasecmp(pvalue, "BINARY")) {
		pvalue = piline->get_first_paramval("ENCODING");
		if (NULL == pvalue || 0 != strcasecmp(pvalue, "BASE64")) {
			return FALSE;
		}
		if (NULL == pmsg->children.pattachments) {
			pattachments = attachment_list_init();
			if (NULL == pattachments) {
				return FALSE;
			}
			message_content_set_attachments_internal(
								pmsg, pattachments);
		} else {
			pattachments = pmsg->children.pattachments;
		}
		pattachment = attachment_content_init();
		if (NULL == pattachment) {
			return FALSE;
		}
		if (FALSE == attachment_list_append_internal(
			pattachments, pattachment)) {
			attachment_content_free(pattachment);
			return FALSE;
		}
		pvalue = piline->get_first_subvalue();
		if (NULL != pvalue) {
			tmp_int32 = strlen(pvalue);
			tmp_bin.pv = malloc(tmp_int32);
			if (tmp_bin.pv == nullptr)
				return FALSE;
			if (decode64(pvalue, tmp_int32, tmp_bin.pv, &decode_len) != 0) {
				free(tmp_bin.pb);
				return FALSE;
			}
			tmp_bin.cb = decode_len;
		} else {
			tmp_bin.cb = 0;
			tmp_bin.pb = NULL;
		}
		propval.proptag = PROP_TAG_ATTACHDATABINARY;
		propval.pvalue = &tmp_bin;
		if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
			return FALSE;
		if (NULL != tmp_bin.pb) {
			free(tmp_bin.pb);
		}
		propval.proptag = PROP_TAG_ATTACHENCODING;
		propval.pvalue = &tmp_bin;
		tmp_bin.cb = 0;
		tmp_bin.pb = NULL;
		if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
			return FALSE;
		pvalue = piline->get_first_paramval("X-FILENAME");
		if (NULL == pvalue) {
			pvalue = piline->get_first_paramval("FILENAME");
		}
		if (NULL == pvalue) {
			sprintf(tmp_buff, "calendar_attachment%d.dat", count);
			pvalue = tmp_buff;
		}
		pvalue1 = strrchr(pvalue, '.');
		if (NULL == pvalue1) {
			pvalue1 = ".dat";
		}
		propval.proptag = PROP_TAG_ATTACHEXTENSION;
		propval.pvalue = deconst(pvalue1);
		if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
			return FALSE;
		propval.proptag = PROP_TAG_ATTACHLONGFILENAME;
		propval.pvalue = deconst(pvalue);
		if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
			return FALSE;
		propval.proptag = PROP_TAG_DISPLAYNAME;
		if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
			return FALSE;
		propval.proptag = PROP_TAG_ATTACHMETHOD;
		propval.pvalue = &tmp_int32;
		tmp_int32 = ATTACH_METHOD_BY_VALUE;
		pvalue1 = piline->get_first_paramval("FMTYPE");
		if (NULL != pvalue1) {
			propval.proptag = PROP_TAG_ATTACHMIMETAG;
			propval.pvalue = deconst(pvalue1);
			if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
				return FALSE;
		}
		propval.proptag = PROP_TAG_ATTACHFLAGS;
		propval.pvalue = &tmp_int32;
		tmp_int32 = 0;
		if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
			return FALSE;
		propval.proptag = PROP_TAG_ATTACHMENTLINKID;
		propval.pvalue = &tmp_int32;
		tmp_int32 = 0;
		if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
			return FALSE;
		propval.proptag = PROP_TAG_ATTACHMENTCONTACTPHOTO;
		propval.pvalue = &tmp_byte;
		tmp_byte = 0;
		if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
			return FALSE;
		propval.proptag = PROP_TAG_ATTACHMENTCONTACTPHOTO;
		propval.pvalue = &tmp_byte;
		tmp_byte = 0;
		if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
			return FALSE;
		propval.proptag = PROP_TAG_EXCEPTIONSTARTTIME;
		propval.pvalue = &tmp_int64;
		tmp_int64 = 0x0CB34557A3DD4000;
		if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
			return FALSE;
		propval.proptag = PROP_TAG_EXCEPTIONENDTIME;
		if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
			return FALSE;
		propval.proptag = PROP_TAG_RENDERINGPOSITION;
		propval.pvalue = &tmp_int32;
		tmp_int32 = 0xFFFFFFFF;
		if (!tpropval_array_set_propval(&pattachment->proplist, &propval))
			return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_parse_valarm(uint32_t reminder_delta,
	time_t start_time, INT_HASH_TABLE *phash,
	uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	uint8_t tmp_byte;
	uint64_t tmp_int64;
	static uint32_t lid;
	static uint32_t lid1;
	static uint32_t lid2;
	static uint32_t lid3;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	/* PidLidReminderDelta */
	lid = 0x00008501;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_LONG, *plast_propid);
	propval.pvalue = &reminder_delta;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	/* PidLidReminderTime */
	lid1 = 0x00008502;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid1;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_SYSTIME, *plast_propid);
	propval.pvalue = &tmp_int64;
	tmp_int64 = rop_util_unix_to_nttime(start_time);
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	/* PidLidReminderSignalTime */
	lid2 = 0x00008560;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid2;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_SYSTIME, *plast_propid);
	propval.pvalue = &tmp_int64;
	tmp_int64 = rop_util_unix_to_nttime(
		start_time - reminder_delta*60);
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	/* PidLidReminderSet */
	lid3 = 0x00008503;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	propname.kind = MNID_ID;
	propname.plid = &lid3;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG(PT_BOOLEAN, *plast_propid);
	propval.pvalue = &tmp_byte;
	tmp_byte = 1;
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_import_internal(const char *str_zone, const char *method,
    BOOL b_proposal, uint16_t calendartype, ICAL *pical,
    std::list<std::shared_ptr<ICAL_COMPONENT>> &pevent_list,
    EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
    USERNAME_TO_ENTRYID username_to_entryid, MESSAGE_CONTENT *pmsg,
    ICAL_TIME *pstart_itime, ICAL_TIME *pend_itime,
    EXCEPTIONINFO *pexception, EXTENDEDEXCEPTION *pext_exception)
{
	int i;
	BOOL b_alarm;
	BOOL b_allday;
	long duration;
	int tmp_count;
	time_t tmp_time;
	time_t end_time;
	ICAL_TIME itime;
	const char *ptzid;
	time_t start_time;
	uint32_t tmp_int32;
	const char *pvalue;
	const char *pvalue1;
	ICAL_TIME end_itime;
	uint16_t last_propid;
	ICAL_TIME start_itime;
	TAGGED_PROPVAL propval;
	MESSAGE_CONTENT *pembedded;
	std::shared_ptr<ICAL_COMPONENT> pmain_event;
	uint32_t deleted_dates[1024];
	uint32_t modified_dates[1024];
	std::shared_ptr<ICAL_COMPONENT> ptz_component;
	ATTACHMENT_LIST *pattachments;
	EXCEPTIONINFO exceptions[1024];
	ATTACHMENT_CONTENT *pattachment;
	EXTENDEDEXCEPTION ext_exceptions[1024];
	APPOINTMENTRECURRENCEPATTERN apprecurr;
	
	if (pevent_list.size() == 1) {
		pmain_event = pevent_list.front();
	} else {
		pmain_event = NULL;
		for (auto event : pevent_list) {
			auto piline = event->get_line("RECURRENCE-ID");
			if (NULL == piline) {
				if (NULL != pmain_event) {
					return FALSE;
				}
				pmain_event = event;
				if (pmain_event->get_line("X-MICROSOFT-RRULE") == nullptr &&
				    pmain_event->get_line("RRULE") == nullptr)
					return FALSE;
			} else {
				if (event->get_line("X-MICROSOFT-RRULE") != nullptr ||
				    event->get_line("RRULE") != nullptr)
					return FALSE;
			}
		}
		if (NULL == pmain_event) {
			return FALSE;
		}
	}
	
	if (NULL != pexception && NULL != pext_exception) {
		memset(pexception, 0, sizeof(EXCEPTIONINFO));
		memset(pext_exception, 0, sizeof(EXTENDEDEXCEPTION));
		pext_exception->changehighlight.size = sizeof(uint32_t);
	}
	
	if (FALSE == oxcical_parse_recipients(
		pmain_event, username_to_entryid, pmsg)) {
		return FALSE;
	}
	
	last_propid = 0x8000;
	INT_HASH_TABLE *phash = int_hash_init(0x1000, sizeof(PROPERTY_NAME));
	if (NULL == phash) {
		return FALSE;
	}
	if (TRUE == b_proposal) {
		if (FALSE == oxcical_parse_proposal(
			phash, &last_propid, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	auto piline = pmain_event->get_line("CATEGORIES");
	if (NULL != piline) {
		if (!oxcical_parse_categories(piline, phash, &last_propid, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	piline = pmain_event->get_line("CLASS");
	if (NULL != piline) {
		if (FALSE == oxcical_parse_class(piline, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	} else {
		propval.proptag = PROP_TAG_SENSITIVITY;
		propval.pvalue = &tmp_int32;
		tmp_int32 = 0;
		if (!tpropval_array_set_propval(&pmsg->proplist, &propval)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	if (NULL != method && (0 == strcasecmp(method, "REPLY") ||
		0 == strcasecmp(method, "COUNTER"))) {
		piline = pmain_event->get_line("COMMENT");
	} else {
		piline = pmain_event->get_line("DESCRIPTION");
	}
	if (NULL != piline) {
		if (FALSE == oxcical_parse_body(piline, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	piline = pmain_event->get_line("X-ALT-DESC");
	if (NULL != piline) {
		pvalue = piline->get_first_paramval("FMTTYPE");
		if (NULL != pvalue && 0 == strcasecmp(pvalue, "text/html")) {
			if (FALSE == oxcical_parse_html(piline, pmsg)) {
				int_hash_free(phash);
				return FALSE;
			}
		}
	}
	
	b_allday = FALSE;
	piline = pmain_event->get_line("X-MICROSOFT-MSNCALENDAR-ALLDAYEVENT");
	if (NULL == piline) {
		piline = pmain_event->get_line("X-MICROSOFT-CDO-ALLDAYEVENT");
	}
	if (NULL != piline) {
		pvalue = piline->get_first_subvalue();
		if (NULL != pvalue && 0 == strcasecmp(pvalue, "TRUE")) {
			b_allday = TRUE;
		}
	}
	
	piline = pmain_event->get_line("DTSTAMP");
	if (NULL != piline) {
		if (FALSE == oxcical_parse_dtstamp(piline,
			method, phash, &last_propid, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	piline = pmain_event->get_line("DTSTART");
	if (NULL == piline) {
		printf("GW-2741: oxcical_import_internal: no DTSTART\n");
		int_hash_free(phash);
		return FALSE;
	}
	pvalue1 = piline->get_first_paramval("VALUE");
	ptzid = piline->get_first_paramval("TZID");
	if (NULL == ptzid) {
		ptz_component = NULL;
	} else {
		ptz_component = oxcical_find_vtimezone(pical, ptzid);
		if (NULL == ptz_component) {
			int_hash_free(phash);
			return FALSE;
		}
		if (FALSE == oxcical_parse_tzdisplay(TRUE,
			ptz_component, phash, &last_propid, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}

	bool b_utc, b_utc_start, b_utc_end;
	if (FALSE == oxcical_parse_dtvalue(ptz_component,
		piline, &b_utc_start, &start_itime, &start_time)) {
		int_hash_free(phash);
		return FALSE;
	}
	if (FALSE == oxcical_parse_start_end(TRUE, b_proposal,
		pmain_event, start_time, phash, &last_propid, pmsg)) {
		int_hash_free(phash);
		return FALSE;
	}
	if (NULL != pstart_itime) {
		*pstart_itime = start_itime;
	}
	
	piline = pmain_event->get_line("DTEND");
	if (NULL != piline) {
		pvalue = piline->get_first_paramval("TZID");
		if ((NULL == pvalue && NULL == ptzid) ||
			(NULL != pvalue && NULL != ptzid &&
			0 == strcasecmp(pvalue, ptzid))) {
			if (FALSE == oxcical_parse_dtvalue(ptz_component,
				piline, &b_utc_end, &end_itime, &end_time)) {
				int_hash_free(phash);
				return FALSE;
			}
		} else {
			int_hash_free(phash);
			return FALSE;
		}
		
		if (end_time < start_time) {
			fprintf(stderr, "GW-2795: ical not imported due to end_time < start_time\n");
			int_hash_free(phash);
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
				ical_add_day(&end_itime, 1);
			}
			ical_itime_to_utc(ptz_component, end_itime, &end_time);
		} else {
			pvalue = piline->get_first_subvalue();
			if (pvalue == nullptr ||
			    !ical_parse_duration(pvalue, &duration) || duration < 0) {
				int_hash_free(phash);
				return FALSE;
			}
			b_utc_end = b_utc_start;
			end_itime = start_itime;
			end_time = start_time + duration;
			ical_add_second(&end_itime, duration);
		}
	}
	
	if (NULL != pend_itime) {
		*pend_itime = end_itime;
	}
	if (NULL != ptz_component) {
		if (FALSE == oxcical_parse_tzdisplay(FALSE,
			ptz_component, phash, &last_propid, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	if (FALSE == oxcical_parse_start_end(FALSE, b_proposal,
		pmain_event, end_time, phash, &last_propid, pmsg)) {
		int_hash_free(phash);
		return FALSE;
	}
	tmp_int32 = (end_time - start_time)/60;
	if (FALSE == oxcical_parse_duration(tmp_int32,
		phash, &last_propid, pmsg)) {
		int_hash_free(phash);
		return FALSE;
	}
	
	if (FALSE == b_allday) {
		if (!b_utc_start && !b_utc_end &&
			0 == start_itime.hour && 0 == start_itime.minute &&
			0 == start_itime.second && 0 == end_itime.hour &&
			0 == end_itime.minute && 0 == end_itime.second &&
			1 == ical_delta_day(end_itime, start_itime)) {
			b_allday = TRUE;
		}
	}
	
	if (TRUE == b_allday) {
		if (FALSE == oxcical_parse_subtype(phash,
			&last_propid, pmsg, pexception)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	memset(&itime, 0, sizeof(ICAL_TIME));
	piline = pmain_event->get_line("RECURRENCE-ID");
	if (NULL != piline) {
		if (NULL != pexception && NULL != pext_exception) {
			if (FALSE == oxcical_parse_recurrence_id(ptz_component,
				piline, phash, &last_propid, pmsg)) {
				int_hash_free(phash);
				return FALSE;
			}
		}
		pvalue = piline->get_first_paramval("TZID");
		if ((NULL != pvalue && NULL != ptzid &&
			0 != strcasecmp(pvalue, ptzid))) {
			int_hash_free(phash);
			return FALSE;
		}
		if (NULL != pvalue) { 
			if (FALSE == oxcical_parse_dtvalue(ptz_component,
				piline, &b_utc, &itime, &tmp_time)) {
				int_hash_free(phash);
				return FALSE;
			}
		} else {
			if (FALSE == oxcical_parse_dtvalue(NULL,
				piline, &b_utc, &itime, &tmp_time)) {
				int_hash_free(phash);
				return FALSE;
			}
			if (!b_utc && (itime.hour != 0 || itime.minute != 0 ||
			    itime.second != 0 || itime.leap_second != 0)) {
				int_hash_free(phash);
				return FALSE;
			}
		}
	}
	
	piline = pmain_event->get_line("UID");
	if (NULL != piline) {
		if (FALSE == oxcical_parse_uid(piline, itime,
			alloc, phash, &last_propid, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	piline = pmain_event->get_line("LOCATION");
	if (NULL != piline) {
		if (FALSE == oxcical_parse_location(piline, phash,
			&last_propid, alloc, pmsg, pexception, pext_exception)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	piline = pmain_event->get_line("ORGANIZER");
	if (NULL != piline) {
		if (FALSE == oxcical_parse_organizer(
			piline, username_to_entryid, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	piline = pmain_event->get_line("X-MICROSOFT-CDO-IMPORTANCE");
	if (NULL == piline) {
		piline = pmain_event->get_line("X-MICROSOFT-MSNCALENDAR-IMPORTANCE");
	}
	if (NULL != piline) {
		pvalue = piline->get_first_subvalue();
		if (NULL != pvalue) {
			tmp_int32 = atoi(pvalue);
			if (0 == tmp_int32 || 1 == tmp_int32 || 2 == tmp_int32) {
				propval.proptag = PROP_TAG_IMPORTANCE;
				propval.pvalue = &tmp_int32;
				if (!tpropval_array_set_propval(&pmsg->proplist, &propval)) {
					int_hash_free(phash);
					return FALSE;
				}
			}
		}
	} else {
		piline = pmain_event->get_line("PRIORITY");
		if (NULL != piline) {
			pvalue = piline->get_first_subvalue();
			if (NULL != pvalue) {
				propval.proptag = PROP_TAG_IMPORTANCE;
				propval.pvalue = &tmp_int32;
				switch (atoi(pvalue)) {
				case 1:
				case 2:
				case 3:
				case 4:
					tmp_int32 = 2;
					if (!tpropval_array_set_propval(&pmsg->proplist, &propval)) {
						int_hash_free(phash);
						return FALSE;
					}
					break;
				case 5:
					tmp_int32 = 1;
					if (!tpropval_array_set_propval(&pmsg->proplist, &propval)) {
						int_hash_free(phash);
						return FALSE;
					}
					break;
				case 6:
				case 7:
				case 8:
				case 9:
					tmp_int32 = 0;
					if (!tpropval_array_set_propval(&pmsg->proplist, &propval)) {
						int_hash_free(phash);
						return FALSE;
					}
					break;
				}
			}
		}
	}
	if (NULL == tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_IMPORTANCE)) {
		propval.proptag = PROP_TAG_IMPORTANCE;
		propval.pvalue = &tmp_int32;
		tmp_int32 = 1;
		if (!tpropval_array_set_propval(&pmsg->proplist, &propval)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	piline = pmain_event->get_line("X-MICROSOFT-CDO-APPT-SEQUENCE");
	if (NULL == piline) {
		piline = pmain_event->get_line("SEQUENCE");
	}
	if (NULL != piline) {
		if (!oxcical_parse_sequence(piline, phash, &last_propid, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	if (method != nullptr && strcasecmp(method, "REQUEST") == 0) {
		if (pmain_event->get_line("X-MICROSOFT-CDO-INTENDEDSTATUS") != nullptr ||
		    pmain_event->get_line("X-MICROSOFT-MSNCALENDAR-INTENDEDSTATUS") != nullptr)
			tmp_int32 = 1;
		else
			tmp_int32 = 2;
	} else {
		tmp_int32 = 0;
	}
	
	piline = pmain_event->get_line("X-MICROSOFT-CDO-BUSYSTATUS");
	if (NULL == piline) {
		piline = pmain_event->get_line("X-MICROSOFT-MSNCALENDAR-BUSYSTATUS");
	}
	if (NULL != piline) {
		if (FALSE == oxcical_parse_busystatus(piline,
			tmp_int32, phash, &last_propid, pmsg, pexception)) {
			int_hash_free(phash);
			return FALSE;
		}
	} else {
		piline = pmain_event->get_line("TRANSP");
		if (NULL != piline) {
			if (FALSE == oxcical_parse_transp(piline,
				tmp_int32, phash, &last_propid, pmsg, pexception)) {
				int_hash_free(phash);
				return FALSE;
			}
		} else {
			piline = pmain_event->get_line("STATUS");
			if (NULL != piline) {
				if (FALSE == oxcical_parse_status(piline,
					tmp_int32, phash, &last_propid, pmsg, pexception)) {
					int_hash_free(phash);
					return FALSE;
				}
			}
		}
	}
	
	piline = pmain_event->get_line("X-MICROSOFT-CDO-OWNERAPPTID");
	if (NULL != piline) {
		if (FALSE == oxcical_parse_ownerapptid(piline, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	piline = pmain_event->get_line("X-MICROSOFT-DISALLOW-COUNTER");
	if (NULL != piline) {
		if (FALSE == oxcical_parse_disallow_counter(
			piline, phash, &last_propid, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	piline = pmain_event->get_line("SUMMARY");
	if (NULL != piline) {
		if (FALSE == oxcical_parse_summary(piline,
			pmsg, alloc, pexception, pext_exception)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	piline = pmain_event->get_line("RRULE");
	if (NULL == piline) {
		piline = pmain_event->get_line("X-MICROSOFT-RRULE");
	}
	if (NULL != piline) {
		if (NULL != ptz_component) {
			if (FALSE == oxcical_parse_recurring_timezone(
				ptz_component, phash, &last_propid, pmsg)) {
				int_hash_free(phash);
				return FALSE;
			}
		}
		memset(&apprecurr, 0, sizeof(APPOINTMENTRECURRENCEPATTERN));
		apprecurr.recurrencepattern.deletedinstancecount = 0;
		apprecurr.recurrencepattern.pdeletedinstancedates = deleted_dates;
		apprecurr.recurrencepattern.modifiedinstancecount = 0;
		apprecurr.recurrencepattern.pmodifiedinstancedates = modified_dates;
		apprecurr.exceptioncount = 0;
		apprecurr.pexceptioninfo = exceptions;
		apprecurr.pextendedexception = ext_exceptions;
		if (FALSE == oxcical_parse_rrule(ptz_component, piline,
			calendartype, start_time, 60*tmp_int32, &apprecurr)) {
			int_hash_free(phash);
			return FALSE;
		}
		piline = pmain_event->get_line("EXDATE");
		if (NULL == piline) {
			piline = pmain_event->get_line("X-MICROSOFT-EXDATE");
		}
		if (NULL != piline) {
			if (FALSE == oxcical_parse_dates(ptz_component, piline,
				&apprecurr.recurrencepattern.deletedinstancecount,
				deleted_dates)) {
				int_hash_free(phash);
				return FALSE;
			}
		}
		piline = pmain_event->get_line("RDATE");
		if (NULL != piline) {
			if (FALSE == oxcical_parse_dates(ptz_component, piline,
				&apprecurr.recurrencepattern.modifiedinstancecount,
				modified_dates)) {
				int_hash_free(phash);
				return FALSE;
			}
			if (apprecurr.recurrencepattern.modifiedinstancecount <
				apprecurr.recurrencepattern.deletedinstancecount) {
				int_hash_free(phash);
				return FALSE;
			}
			apprecurr.exceptioncount =
				apprecurr.recurrencepattern.modifiedinstancecount;
			for (i=0; i<apprecurr.exceptioncount; i++) {
				memset(exceptions + i, 0, sizeof(EXCEPTIONINFO));
				memset(ext_exceptions + i, 0, sizeof(EXTENDEDEXCEPTION));
				exceptions[i].startdatetime = modified_dates[i];
				exceptions[i].enddatetime = modified_dates[i] +
									(end_time - start_time)/60;
				exceptions[i].originalstartdate = deleted_dates[i];
				exceptions[i].overrideflags = 0;
				ext_exceptions[i].changehighlight.size = sizeof(uint32_t);
			}
		} else {
			apprecurr.exceptioncount = 0;
		}
		
		if (pevent_list.size() > 1) {
			pattachments = attachment_list_init();
			if (NULL == pattachments) {
				int_hash_free(phash);
				return FALSE;
			}
			message_content_set_attachments_internal(pmsg, pattachments);
		}
		for (auto event : pevent_list) {
			if (event == pmain_event)
				continue;
			pattachment = attachment_content_init();
			if (NULL == pattachment) {
				int_hash_free(phash);
				return FALSE;
			}
			if (FALSE == attachment_list_append_internal(
				pattachments, pattachment)) {
				attachment_content_free(pattachment);
				int_hash_free(phash);
				return FALSE;
			}
			pembedded = message_content_init();
			if (NULL == pembedded) {
				int_hash_free(phash);
				return FALSE;
			}
			attachment_content_set_embedded_internal(pattachment, pembedded);
			propval.proptag = PROP_TAG_MESSAGECLASS;
			propval.pvalue  = deconst("IPM.OLE.CLASS.{00061055-0000-0000-C000-000000000046}");
			if (!tpropval_array_set_propval(&pembedded->proplist, &propval)) {
				int_hash_free(phash);
				return FALSE;
			}
			
			std::list<std::shared_ptr<ICAL_COMPONENT>> tmp_list;
			try {
				tmp_list.push_back(event);
			} catch (...) {
				int_hash_free(phash);
				return false;
			}
			if (!oxcical_import_internal(str_zone, method, false,
			    calendartype, pical, tmp_list, alloc, get_propids,
			    username_to_entryid, pembedded, &start_itime,
			    &end_itime, exceptions + apprecurr.exceptioncount,
			    ext_exceptions + apprecurr.exceptioncount)) {
				int_hash_free(phash);
				return FALSE;
			}
			
			if (!oxcical_parse_exceptional_attachment(pattachment,
			    event, start_itime, end_itime, pmsg)) {
				int_hash_free(phash);
				return FALSE;
			}
			
			piline = event->get_line("RECURRENCE-ID");
			if (FALSE == oxcical_parse_dtvalue(ptz_component,
				piline, &b_utc, &itime, &tmp_time)) {
				int_hash_free(phash);
				return FALSE;
			}
			tmp_int32 = rop_util_unix_to_nttime(tmp_time)/600000000;
			for (i=0; i<apprecurr.recurrencepattern.
				deletedinstancecount; i++) {
				if (tmp_int32 == deleted_dates[i]) {
					break;
				}
			}
			if (i < apprecurr.recurrencepattern.deletedinstancecount) {
				continue;
			}
			deleted_dates[apprecurr.recurrencepattern.
					deletedinstancecount] = tmp_int32;
			apprecurr.recurrencepattern.deletedinstancecount ++;
			if (apprecurr.recurrencepattern.deletedinstancecount >= 1024) {
				int_hash_free(phash);
				return FALSE;
			}
			exceptions[apprecurr.exceptioncount
				].originalstartdate = tmp_int32;
			ext_exceptions[apprecurr.exceptioncount
					].originalstartdate = tmp_int32;
			ical_itime_to_utc(NULL, start_itime, &tmp_time);
			tmp_int32 = rop_util_unix_to_nttime(tmp_time)/600000000;
			modified_dates[apprecurr.recurrencepattern.
					modifiedinstancecount] = tmp_int32; 
			apprecurr.recurrencepattern.modifiedinstancecount ++;
			exceptions[apprecurr.exceptioncount
					].startdatetime = tmp_int32;
			ext_exceptions[apprecurr.exceptioncount
						].startdatetime = tmp_int32;
			ical_itime_to_utc(NULL, end_itime, &tmp_time);
			tmp_int32 = rop_util_unix_to_nttime(tmp_time)/600000000;
			exceptions[apprecurr.exceptioncount
					].enddatetime = tmp_int32;
			ext_exceptions[apprecurr.exceptioncount
						].enddatetime = tmp_int32;
			apprecurr.exceptioncount ++;
		}
		qsort(deleted_dates, apprecurr.recurrencepattern.
			deletedinstancecount, sizeof(uint32_t), oxcical_cmp_date);
		qsort(modified_dates, apprecurr.recurrencepattern.
			modifiedinstancecount, sizeof(uint32_t), oxcical_cmp_date);
		qsort(exceptions, apprecurr.exceptioncount,
			sizeof(EXCEPTIONINFO), oxcical_cmp_exception);
		qsort(ext_exceptions, apprecurr.exceptioncount,
			sizeof(EXTENDEDEXCEPTION), oxcical_cmp_ext_exception);
		if (FALSE == oxcical_parse_appointment_recurrence(
			&apprecurr, phash, &last_propid, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	tmp_count = 0;
	for (auto piline : pmain_event->line_list) {
		if (strcasecmp(piline->name.c_str(), "ATTACH") != 0)
			continue;
		tmp_count ++;
		if (FALSE == oxcical_parse_attachment(piline, tmp_count, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	b_alarm = FALSE;
	if (pmain_event->component_list.size() > 0) {
		auto palarm_component = pmain_event->component_list.front();
		if (strcasecmp(palarm_component->name.c_str(), "VALARM") == 0) {
			b_alarm = TRUE;
			piline = palarm_component->get_line("TRIGGER");
			if (piline == nullptr ||
			    (pvalue = piline->get_first_subvalue()) == nullptr) {
				if (FALSE == b_allday) {
					tmp_int32 = 15;
				} else {
					tmp_int32 = 1080;
				}
			} else {
				pvalue1 = piline->get_first_paramval("RELATED");
				if (NULL == pvalue1) {
					pvalue1 = piline->get_first_paramval("VALUE");
					if ((pvalue1 == nullptr ||
					    strcasecmp(pvalue1, "DATE-TIME") == 0) &&
					    ical_datetime_to_utc(ptz_component, pvalue, &tmp_time)) {
						tmp_int32 = abs(start_time - tmp_time)/60;
					} else {
						if (FALSE == b_allday) {
							tmp_int32 = 15;
						} else {
							tmp_int32 = 1080;
						}
					}
				} else {
					if (0 != strcasecmp(pvalue1, "START") ||
					    !ical_parse_duration(pvalue, &duration)) {
						if (FALSE == b_allday) {
							tmp_int32 = 15;
						} else {
							tmp_int32 = 1080;
						}
					} else {
						tmp_int32 = abs(duration)/60;
					}
				}
			}
			if (FALSE == oxcical_parse_valarm(tmp_int32,
				start_time, phash, &last_propid, pmsg)) {
				int_hash_free(phash);
				return FALSE;
			}
		}
	}
	
	if (NULL != pexception) {
		if (FALSE == b_alarm) {
			pexception->overrideflags |= OVERRIDEFLAG_REMINDER;
			pexception->reminderset = 0;
		} else {
			pexception->overrideflags |= OVERRIDEFLAG_REMINDERDELTA;
			pexception->reminderdelta = tmp_int32;
		}
	}
	
	if (FALSE == oxcical_fetch_propname(
		pmsg, phash, alloc, get_propids)) {
		int_hash_free(phash);
		return FALSE;
	}
	int_hash_free(phash);
	return TRUE;
}

static BOOL oxcical_import_events(const char *str_zone, uint16_t calendartype,
    ICAL *pical, std::list<std::shared_ptr<UID_EVENTS>> &pevents_list,
    EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
    USERNAME_TO_ENTRYID username_to_entryid, MESSAGE_CONTENT *pmsg)
{
	TAGGED_PROPVAL propval;
	MESSAGE_CONTENT *pembedded;
	ATTACHMENT_LIST *pattachments;
	ATTACHMENT_CONTENT *pattachment;
	
	pattachments = attachment_list_init();
	if (NULL == pattachments) {
		return FALSE;
	}
	message_content_set_attachments_internal(pmsg, pattachments);
	for (auto puid_events : pevents_list) {
		pattachment = attachment_content_init();
		if (NULL == pattachment) {
			return FALSE;
		}
		if (FALSE == attachment_list_append_internal(
			pattachments, pattachment)) {
			attachment_content_free(pattachment);
			return FALSE;
		}
		pembedded = message_content_init();
		if (NULL == pembedded) {
			return FALSE;
		}
		attachment_content_set_embedded_internal(pattachment, pembedded);
		propval.proptag = PROP_TAG_MESSAGECLASS;
		propval.pvalue  = deconst("IPM.Appointment");
		if (!tpropval_array_set_propval(&pembedded->proplist, &propval))
			return FALSE;
		if (!oxcical_import_internal(str_zone, "PUBLISH", false,
		    calendartype, pical, puid_events->list, alloc, get_propids,
		    username_to_entryid, pembedded, nullptr, nullptr, nullptr,
		    nullptr))
			return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_classify_calendar(ICAL *pical,
    std::list<std::shared_ptr<UID_EVENTS>> &pevent_uid_list)
{
	
	for (auto pcomponent : pical->component_list) {
		if (strcasecmp(pcomponent->name.c_str(), "VEVENT") != 0)
			continue;
		std::shared_ptr<UID_EVENTS> puid_events;
		auto piline = pcomponent->get_line("UID");
		auto puid = piline != nullptr ? piline->get_first_subvalue() : nullptr;
		if (puid != nullptr) {
			auto i = std::find_if(pevent_uid_list.cbegin(), pevent_uid_list.cend(),
			         [=](const auto &e) { return e->puid != nullptr && strcmp(e->puid, puid) == 0; });
			if (i != pevent_uid_list.cend())
				puid_events = *i;
		}
		if (puid_events == nullptr) try {
			puid_events = std::make_shared<UID_EVENTS>();
			puid_events->puid = puid;
			pevent_uid_list.push_back(puid_events);
		} catch (...) {
			return false;
		}
		try {
			puid_events->list.push_back(pcomponent);
		} catch (...) {
			return false;
		}
	}
	return TRUE;
}

static const char *oxcical_get_partstat(const std::list<std::shared_ptr<UID_EVENTS>> &pevents_list)
{
	if (pevents_list.size() == 0)
		return nullptr;
	for (auto event : pevents_list.front()->list) {
		auto piline = event->get_line("ATTENDEE");
		if (NULL != piline) {
			return piline->get_first_paramval("PARTSTAT");
		}
	}
	return NULL;
}

static uint32_t oxcical_get_calendartype(std::shared_ptr<ICAL_LINE> piline)
{
	const char *pvalue;
	
	if (NULL == piline) {
		return CALENDARTYPE_DEFAULT;
	}
	pvalue = piline->get_first_subvalue();
	if (NULL == pvalue) {
		return CALENDARTYPE_DEFAULT;
	}
	if (0 == strcasecmp(pvalue, "Gregorian")) {
		return CALENDARTYPE_GREGORIAN;
	} else if (0 == strcasecmp(pvalue, "Gregorian_us")) {
		return CALENDARTYPE_GREGORIAN_US;
	} else if (0 == strcasecmp(pvalue, "Japan")) {
		return CALENDARTYPE_JAPAN;
	} else if (0 == strcasecmp(pvalue, "Taiwan")) {
		return CALENDARTYPE_TAIWAN;
	} else if (0 == strcasecmp(pvalue, "Korea")) {
		return CALENDARTYPE_KOREA;
	} else if (0 == strcasecmp(pvalue, "Hijri")) {
		return CALENDARTYPE_HIJRI;
	} else if (0 == strcasecmp(pvalue, "Thai")) {
		return CALENDARTYPE_THAI;
	} else if (0 == strcasecmp(pvalue, "Hebrew")) {
		return CALENDARTYPE_HEBREW;
	} else if (0 == strcasecmp(pvalue, "GregorianMeFrench")) {
		return CALENDARTYPE_GREGORIAN_ME_FRENCH;
	} else if (0 == strcasecmp(pvalue, "GregorianArabic")) {
		return CALENDARTYPE_GREGORIAN_ARABIC;
	} else if (0 == strcasecmp(pvalue, "GregorianXlitEnglish")) {
		return CALENDARTYPE_GREGORIAN_XLIT_ENGLISH;
	} else if (0 == strcasecmp(pvalue, "GregorianXlitFrench")) {
		return CALENDARTYPE_GREGORIAN_XLIT_FRENCH;
	} else if (0 == strcasecmp(pvalue, "JapanLunar")) {
		return CALENDARTYPE_LUNAR_JAPANESE;
	} else if (0 == strcasecmp(pvalue, "ChineseLunar")) {
		return CALENDARTYPE_CHINESE_LUNAR;
	} else if (0 == strcasecmp(pvalue, "Saka")) {
		return CALENDARTYPE_SAKA;
	} else if (0 == strcasecmp(pvalue, "LunarEtoChn")) {
		return CALENDARTYPE_LUNAR_ETO_CHN;
	} else if (0 == strcasecmp(pvalue, "LunarEtoKor")) {
		return CALENDARTYPE_LUNAR_ETO_KOR;
	} else if (0 == strcasecmp(pvalue, "LunaRokuyou")) {
		return CALENDARTYPE_LUNAR_ETO_ROKUYOU;
	} else if (0 == strcasecmp(pvalue, "KoreaLunar")) {
		return CALENDARTYPE_LUNAR_KOREAN;
	} else if (0 == strcasecmp(pvalue, "Umalqura")) {
		return CALENDARTYPE_UMALQURA;
	}
	return CALENDARTYPE_DEFAULT;
}

MESSAGE_CONTENT* oxcical_import(
	const char *str_zone, const ICAL *pical,
	EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
	USERNAME_TO_ENTRYID username_to_entryid)
{
	BOOL b_proposal;
	const char *pvalue = nullptr, *pvalue1 = nullptr;
	uint16_t calendartype;
	MESSAGE_CONTENT *pmsg;
	TAGGED_PROPVAL propval;
	std::list<std::shared_ptr<UID_EVENTS>> events_list;
	
	b_proposal = FALSE;
	pmsg = message_content_init();
	if (NULL == pmsg) {
		return NULL;
	}
	auto piline = const_cast<ICAL *>(pical)->get_line("X-MICROSOFT-CALSCALE");
	calendartype = oxcical_get_calendartype(piline);
	if (!oxcical_classify_calendar(deconst(pical), events_list) ||
	    events_list.size() == 0)
		goto IMPORT_FAILURE;
	propval.proptag = PROP_TAG_MESSAGECLASS;
	piline = const_cast<ICAL *>(pical)->get_line("METHOD");
	propval.pvalue = deconst("IPM.Appointment");
	if (NULL != piline) {
		pvalue = piline->get_first_subvalue();
		if (NULL != pvalue) {
			if (0 == strcasecmp(pvalue, "PUBLISH")) {
				if (events_list.size() > 1) {
					if (!oxcical_import_events(str_zone,
					    calendartype, deconst(pical),
					    events_list, alloc, get_propids,
					    username_to_entryid, pmsg))
						goto IMPORT_FAILURE;
					return pmsg;
				}
				propval.pvalue = deconst("IPM.Appointment");
			} else if (0 == strcasecmp(pvalue, "REQUEST")) {
				if (events_list.size() != 1)
					goto IMPORT_FAILURE;
				propval.pvalue = deconst("IPM.Schedule.Meeting.Request");
			} else if (0 == strcasecmp(pvalue, "REPLY")) {
				if (events_list.size() != 1)
					goto IMPORT_FAILURE;
				pvalue1 = oxcical_get_partstat(events_list);
				if (NULL != pvalue1) {
					if (0 == strcasecmp(pvalue1, "ACCEPTED")) {
						propval.pvalue = deconst("IPM.Schedule.Meeting.Resp.Pos");
					} else if (0 == strcasecmp(pvalue1, "TENTATIVE")) {
						propval.pvalue = deconst("IPM.Schedule.Meeting.Resp.Tent");
					} else if (0 == strcasecmp(pvalue1, "DECLINED")) {
						propval.pvalue = deconst("IPM.Schedule.Meeting.Resp.Neg");
					}
				}
			} else if (0 == strcasecmp(pvalue, "COUNTER")) {
				if (events_list.size() != 1)
					goto IMPORT_FAILURE;
				pvalue1 = oxcical_get_partstat(events_list);
				if (NULL != pvalue1 && 0 == strcasecmp(pvalue1, "TENTATIVE")) {
					propval.pvalue = deconst("IPM.Schedule.Meeting.Resp.Tent");
					b_proposal = TRUE;
				}
			} else if (0 == strcasecmp(pvalue, "CANCEL")) {
				propval.pvalue = deconst("IPM.Schedule.Meeting.Canceled");
			}
		}
	} else {
		if (events_list.size() > 1) {
			if (!oxcical_import_events(str_zone, calendartype,
			    deconst(pical), events_list, alloc, get_propids,
			    username_to_entryid, pmsg))
				goto IMPORT_FAILURE;
			return pmsg;
		}
	}
	if (!tpropval_array_set_propval(&pmsg->proplist, &propval))
		goto IMPORT_FAILURE;
	if (oxcical_import_internal(str_zone, pvalue, b_proposal, calendartype,
	    deconst(pical), events_list.front()->list, alloc, get_propids,
	    username_to_entryid, pmsg, nullptr, nullptr, nullptr, nullptr))
		return pmsg;
 IMPORT_FAILURE:
	message_content_free(pmsg);
	return NULL;
}

static std::shared_ptr<ICAL_COMPONENT> oxcical_export_timezone(ICAL *pical,
	int year, const char *tzid, TIMEZONESTRUCT *ptzstruct)
{
	int day;
	int order;
	int utc_offset;
	std::shared_ptr<ICAL_VALUE> pivalue;
	char tmp_buff[1024];
	
	auto pcomponent = ical_new_component("VTIMEZONE");
	if (NULL == pcomponent) {
		return NULL;
	}
	pical->append_comp(pcomponent);
	auto piline = ical_new_simple_line("TZID", tzid);
	if (NULL == piline) {
		return NULL;
	}
	if (pcomponent->append_line(piline) < 0)
		return nullptr;
	/* STANDARD component */
	auto pcomponent1 = ical_new_component("STANDARD");
	if (NULL == pcomponent1) {
		return NULL;
	}
	pcomponent->append_comp(pcomponent1);
	if (0 == ptzstruct->daylightdate.month) {
		strcpy(tmp_buff, "16010101T000000");
	} else {
		if (0 == ptzstruct->standarddate.year) {
			day = ical_get_dayofmonth(year,
				ptzstruct->standarddate.month,
				ptzstruct->standarddate.day,
				ptzstruct->standarddate.dayofweek);
			sprintf(tmp_buff, "%04d%02d%02dT%02d%02d%02d",
				year, (int)ptzstruct->standarddate.month,
				day, (int)ptzstruct->standarddate.hour,
				(int)ptzstruct->standarddate.minute,
				(int)ptzstruct->standarddate.second);
		} else if (1 == ptzstruct->standarddate.year) {
			sprintf(tmp_buff, "%04d%02d%02dT%02d%02d%02d",
				year, (int)ptzstruct->standarddate.month,
				(int)ptzstruct->standarddate.day,
				(int)ptzstruct->standarddate.hour,
				(int)ptzstruct->standarddate.minute,
				(int)ptzstruct->standarddate.second);
		} else {
			return NULL;
		}
	}
	piline = ical_new_simple_line("DTSTART", tmp_buff);
	if (NULL == piline) {
		return NULL;
	}
	if (pcomponent1->append_line(piline) < 0)
		return nullptr;
	if (0 != ptzstruct->daylightdate.month) {
		if (0 == ptzstruct->standarddate.year) {
			piline = ical_new_line("RRULE");
			if (NULL == piline) {
				return NULL;
			}
			if (pcomponent1->append_line(piline) < 0)
				return nullptr;
			pivalue = ical_new_value("FREQ");
			if (NULL == pivalue) {
				return NULL;
			}
			if (piline->append_value(pivalue) < 0)
				return nullptr;
			if (!pivalue->append_subval("YEARLY"))
				return NULL;
			pivalue = ical_new_value("BYDAY");
			if (NULL == pivalue) {
				return NULL;
			}
			if (piline->append_value(pivalue) < 0)
				return nullptr;
			order = ptzstruct->standarddate.day;
			if (5 == order) {
				order = -1;
			}
			switch (ptzstruct->standarddate.dayofweek) {
			case 0:
				sprintf(tmp_buff, "%dSU", order);
				break;
			case 1:
				sprintf(tmp_buff, "%dMO", order);
				break;
			case 2:
				sprintf(tmp_buff, "%dTU", order);
				break;
			case 3:
				sprintf(tmp_buff, "%dWE", order);
				break;
			case 4:
				sprintf(tmp_buff, "%dTH", order);
				break;
			case 5:
				sprintf(tmp_buff, "%dFR", order);
				break;
			case 6:
				sprintf(tmp_buff, "%dSA", order);
				break;
			default:
				return NULL;
			}
			if (!pivalue->append_subval(tmp_buff))
				return NULL;
			pivalue = ical_new_value("BYMONTH");
			if (NULL == pivalue) {
				return NULL;
			}
			if (piline->append_value(pivalue) < 0)
				return nullptr;
			sprintf(tmp_buff, "%d", (int)ptzstruct->standarddate.month);
			if (!pivalue->append_subval(tmp_buff))
				return NULL;
		} else if (1 == ptzstruct->standarddate.year) {
			piline = ical_new_line("RRULE");
			if (NULL == piline) {
				return NULL;
			}
			if (pcomponent1->append_line(piline) < 0)
				return nullptr;
			pivalue = ical_new_value("FREQ");
			if (NULL == pivalue) {
				return NULL;
			}
			if (piline->append_value(pivalue) < 0)
				return nullptr;
			if (!pivalue->append_subval("YEARLY"))
				return NULL;
			pivalue = ical_new_value("BYMONTHDAY");
			if (NULL == pivalue) {
				return NULL;
			}
			if (piline->append_value(pivalue) < 0)
				return nullptr;
			sprintf(tmp_buff, "%d", (int)ptzstruct->standarddate.day);
			pivalue = ical_new_value("BYMONTH");
			if (NULL == pivalue) {
				return NULL;
			}
			if (piline->append_value(pivalue) < 0)
				return nullptr;
			sprintf(tmp_buff, "%d", (int)ptzstruct->standarddate.month);
			if (!pivalue->append_subval(tmp_buff))
				return NULL;
		}
	}
	utc_offset = (-1)*(ptzstruct->bias + ptzstruct->daylightbias);
	if (utc_offset >= 0) {
		tmp_buff[0] = '+';
	} else {
		tmp_buff[0] = '-';
	}
	utc_offset = abs(utc_offset);
	sprintf(tmp_buff + 1, "%02d%02d", utc_offset/60, utc_offset%60);
	piline = ical_new_simple_line("TZOFFSETFROM", tmp_buff);
	if (piline == nullptr)
		return nullptr;
	if (pcomponent1->append_line(piline) < 0)
		return nullptr;
	utc_offset = (-1)*(ptzstruct->bias + ptzstruct->standardbias);
	if (utc_offset >= 0) {
		tmp_buff[0] = '+';
	} else {
		tmp_buff[0] = '-';
	}
	utc_offset = abs(utc_offset);
	sprintf(tmp_buff + 1, "%02d%02d", utc_offset/60, utc_offset%60);
	piline = ical_new_simple_line("TZOFFSETTO", tmp_buff);
	if (pcomponent1->append_line(piline) < 0)
		return nullptr;
	if (0 == ptzstruct->daylightdate.month) {
		return pcomponent;
	}
	/* DAYLIGHT component */
	pcomponent1 = ical_new_component("DAYLIGHT");
	if (NULL == pcomponent1) {
		return NULL;
	}
	pcomponent->append_comp(pcomponent1);
	if (0 == ptzstruct->daylightdate.year) {
		day = ical_get_dayofmonth(year,
			ptzstruct->daylightdate.month,
			ptzstruct->daylightdate.day,
			ptzstruct->daylightdate.dayofweek);
		sprintf(tmp_buff, "%04d%02d%02dT%02d%02d%02d",
			year, (int)ptzstruct->daylightdate.month,
			day, (int)ptzstruct->daylightdate.hour,
			(int)ptzstruct->daylightdate.minute,
			(int)ptzstruct->daylightdate.second);
	} else if (1 == ptzstruct->daylightdate.year) {
		sprintf(tmp_buff, "%04d%02d%02dT%02d%02d%02d",
			year, (int)ptzstruct->daylightdate.month,
			(int)ptzstruct->daylightdate.day,
			(int)ptzstruct->daylightdate.hour,
			(int)ptzstruct->daylightdate.minute,
			(int)ptzstruct->daylightdate.second);
	} else {
		return NULL;
	}
	piline = ical_new_simple_line("DTSTART", tmp_buff);
	if (NULL == piline) {
		return NULL;
	}
	if (pcomponent1->append_line(piline) < 0)
		return nullptr;
	if (0 == ptzstruct->daylightdate.year) {
		piline = ical_new_line("RRULE");
		if (NULL == piline) {
			return NULL;
		}
		if (pcomponent1->append_line(piline) < 0)
			return nullptr;
		pivalue = ical_new_value("FREQ");
		if (NULL == pivalue) {
			return NULL;
		}
		if (piline->append_value(pivalue) < 0)
			return nullptr;
		if (!pivalue->append_subval("YEARLY"))
			return NULL;
		pivalue = ical_new_value("BYDAY");
		if (NULL == pivalue) {
			return NULL;
		}
		if (piline->append_value(pivalue) < 0)
			return nullptr;
		order = ptzstruct->daylightdate.day;
		if (5 == order) {
			order = -1;
		}
		switch (ptzstruct->daylightdate.dayofweek) {
		case 0:
			sprintf(tmp_buff, "%dSU", order);
			break;
		case 1:
			sprintf(tmp_buff, "%dMO", order);
			break;
		case 2:
			sprintf(tmp_buff, "%dTU", order);
			break;
		case 3:
			sprintf(tmp_buff, "%dWE", order);
			break;
		case 4:
			sprintf(tmp_buff, "%dTH", order);
			break;
		case 5:
			sprintf(tmp_buff, "%dFR", order);
			break;
		case 6:
			sprintf(tmp_buff, "%dSA", order);
			break;
		default:
			return NULL;
		}
		if (!pivalue->append_subval(tmp_buff))
			return NULL;
		pivalue = ical_new_value("BYMONTH");
		if (NULL == pivalue) {
			return NULL;
		}
		if (piline->append_value(pivalue) < 0)
			return nullptr;
		sprintf(tmp_buff, "%d", (int)ptzstruct->daylightdate.month);
		if (!pivalue->append_subval(tmp_buff))
			return NULL;
	} else if (1 == ptzstruct->daylightdate.year) {
		piline = ical_new_line("RRULE");
		if (NULL == piline) {
			return NULL;
		}
		if (pcomponent1->append_line(piline) < 0)
			return nullptr;
		pivalue = ical_new_value("FREQ");
		if (NULL == pivalue) {
			return NULL;
		}
		if (piline->append_value(pivalue) < 0)
			return nullptr;
		if (!pivalue->append_subval("YEARLY"))
			return NULL;
		pivalue = ical_new_value("BYMONTHDAY");
		if (NULL == pivalue) {
			return NULL;
		}
		if (piline->append_value(pivalue) < 0)
			return nullptr;
		sprintf(tmp_buff, "%d", (int)ptzstruct->daylightdate.day);
		pivalue = ical_new_value("BYMONTH");
		if (NULL == pivalue) {
			return NULL;
		}
		if (piline->append_value(pivalue) < 0)
			return nullptr;
		sprintf(tmp_buff, "%d", (int)ptzstruct->daylightdate.month);
		if (!pivalue->append_subval(tmp_buff))
			return NULL;
	}
	utc_offset = (-1)*(ptzstruct->bias + ptzstruct->standardbias);
	if (utc_offset >= 0) {
		tmp_buff[0] = '+';
	} else {
		tmp_buff[0] = '-';
	}
	utc_offset = abs(utc_offset);
	sprintf(tmp_buff + 1, "%02d%02d", utc_offset/60, utc_offset%60);
	piline = ical_new_simple_line("TZOFFSETFROM", tmp_buff);
	if (piline == nullptr)
		return nullptr;
	if (pcomponent1->append_line(piline) < 0)
		return nullptr;
	utc_offset = (-1)*(ptzstruct->bias + ptzstruct->daylightbias);
	if (utc_offset >= 0) {
		tmp_buff[0] = '+';
	} else {
		tmp_buff[0] = '-';
	}
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
	EXT_BUFFER_ALLOC alloc, char *username)
{
	void *pvalue;
	
	pvalue = tpropval_array_get_propval(prcpt, PROP_TAG_SMTPADDRESS);
	if (NULL == pvalue) {
		pvalue = tpropval_array_get_propval(
				prcpt, PROP_TAG_ADDRESSTYPE);
		if (NULL == pvalue) {
 FIND_ENTRYID:
			pvalue = tpropval_array_get_propval(
				prcpt, PROP_TAG_ENTRYID);
			if (NULL == pvalue) {
				return FALSE;
			}
			return entryid_to_username(static_cast<BINARY *>(pvalue), alloc, username);
		} else {
			if (strcasecmp(static_cast<char *>(pvalue), "SMTP") == 0) {
				pvalue = tpropval_array_get_propval(
						prcpt, PROP_TAG_EMAILADDRESS);
			} else if (strcasecmp(static_cast<char *>(pvalue), "EX") == 0) {
				pvalue = tpropval_array_get_propval(
						prcpt, PROP_TAG_EMAILADDRESS);
				if (NULL != pvalue) {
					if (essdn_to_username(static_cast<char *>(pvalue), username))
						return TRUE;
					pvalue = NULL;
				}
			} else {
				pvalue = NULL;
			}
			if (NULL == pvalue) {
				goto FIND_ENTRYID;
			}
		}
	}
	strncpy(username, static_cast<char *>(pvalue), 128);
	return TRUE;
}

static BOOL oxcical_export_recipient_table(std::shared_ptr<ICAL_COMPONENT> pevent_component,
	ENTRYID_TO_USERNAME entryid_to_username,
	ESSDN_TO_USERNAME essdn_to_username,
	EXT_BUFFER_ALLOC alloc, const char *partstat,
	MESSAGE_CONTENT *pmsg)
{
	int i;
	BOOL b_rsvp;
	void *pvalue;
	std::shared_ptr<ICAL_LINE> piline;
	char username[128];
	char tmp_value[256];
	std::shared_ptr<ICAL_PARAM> piparam;
	std::shared_ptr<ICAL_VALUE> pivalue;
	
	if (NULL == pmsg->children.prcpts) {
		return TRUE;
	}
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_MESSAGECLASS);
	if (NULL == pvalue) {
		pvalue = tpropval_array_get_propval(
			&pmsg->proplist, PROP_TAG_MESSAGECLASS_STRING8);
	}
	if (NULL == pvalue) {
		return FALSE;
	}
	/* ignore ATTENDEE when METHOD is "PUBLIC" */
	if (strcasecmp(static_cast<char *>(pvalue), "IPM.Appointment") == 0)
		return TRUE;
	if (strcasecmp(static_cast<char *>(pvalue), "IPM.Schedule.Meeting.Resp.Pos") == 0 ||
	    strcasecmp(static_cast<char *>(pvalue), "IPM.Schedule.Meeting.Resp.Tent") == 0 ||
	    strcasecmp(static_cast<char *>(pvalue), "IPM.Schedule.Meeting.Resp.Neg") == 0) {
		pvalue = tpropval_array_get_propval(&pmsg->proplist,
					PROP_TAG_SENTREPRESENTINGSMTPADDRESS);
		if (NULL == pvalue) {
			return FALSE;
		}
		piline = ical_new_line("ATTENDEE");
		if (NULL == piline) {
			return FALSE;
		}
		if (pevent_component->append_line(piline) < 0)
			return false;
		piparam = ical_new_param("PARTSTAT");
		if (NULL == piparam) {
			return FALSE;
		}
		if (piline->append_param(piparam) < 0)
			return false;
		if (!piparam->append_paramval(partstat))
			return FALSE;
		snprintf(tmp_value, sizeof(tmp_value), "MAILTO:%s", static_cast<const char *>(pvalue));
		pivalue = ical_new_value(NULL);
		if (NULL == pivalue) {
			return FALSE;
		}
		if (piline->append_value(pivalue) < 0)
			return false;
		return pivalue->append_subval(tmp_value) ? TRUE : false;
	}	
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_RESPONSEREQUESTED);
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		b_rsvp = TRUE;
	} else {
		b_rsvp = FALSE;
	}
	for (i=0; i<pmsg->children.prcpts->count; i++) {
		pvalue = tpropval_array_get_propval(
			pmsg->children.prcpts->pparray[i],
			PROP_TAG_RECIPIENTFLAGS);
		if (NULL == pvalue) {
			continue;
		}
		if ((*(uint32_t*)pvalue) & 0x00000020 ||
			(*(uint32_t*)pvalue) & 0x00000002) {
			continue;
		}
		pvalue = tpropval_array_get_propval(
			pmsg->children.prcpts->pparray[i],
			PROP_TAG_RECIPIENTTYPE);
		if (NULL != pvalue && 0 == *(uint32_t*)pvalue) {
			continue;
		}
		piline = ical_new_line("ATTENDEE");
		if (NULL == piline) {
			return FALSE;
		}
		if (pevent_component->append_line(piline) < 0)
			return false;
		piparam = ical_new_param("ROLE");
		if (NULL == piparam) {
			return FALSE;
		}
		if (piline->append_param(piparam) < 0)
			return false;
		if (NULL != pvalue && 0x00000002 == *(uint32_t*)pvalue) {
			if (!piparam->append_paramval("OPT-PARTICIPANT"))
				return FALSE;
		} else if (NULL != pvalue && 0x00000003 == *(uint32_t*)pvalue) {
			if (!piparam->append_paramval("NON-PARTICIPANT"))
				return FALSE;
		} else {
			if (!piparam->append_paramval("REQ-PARTICIPANT"))
				return FALSE;
		}
		if (NULL != partstat) {
			piparam = ical_new_param("PARTSTAT");
			if (NULL == piparam) {
				return FALSE;
			}
			if (piline->append_param(piparam) < 0)
				return false;
			if (!piparam->append_paramval(partstat))
				return FALSE;
		}
		if (TRUE == b_rsvp) {
			piparam = ical_new_param("RSVP");
			if (NULL == piparam) {
				return FALSE;
			}
			if (piline->append_param(piparam) < 0)
				return false;
			if (!piparam->append_paramval("TRUE"))
				return FALSE;
		}
		pvalue = tpropval_array_get_propval(
			pmsg->children.prcpts->pparray[i],
			PROP_TAG_DISPLAYNAME);
		if (NULL != pvalue) {
			piparam = ical_new_param("CN");
			if (NULL == piparam) {
				return FALSE;
			}
			if (piline->append_param(piparam) < 0)
				return false;
			if (!piparam->append_paramval(static_cast<char *>(pvalue)))
				return FALSE;
		}
		if (FALSE == oxcical_get_smtp_address(
			pmsg->children.prcpts->pparray[i],
			entryid_to_username, essdn_to_username,
			alloc, username)) {
			return FALSE;
		}
		sprintf(tmp_value, "MAILTO:%s", username);
		pivalue = ical_new_value(NULL);
		if (NULL == pivalue) {
			return FALSE;
		}
		if (piline->append_value(pivalue) < 0)
			return false;
		if (!pivalue->append_subval(tmp_value))
			return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_export_rrule(std::shared_ptr<ICAL_COMPONENT> ptz_component,
    std::shared_ptr<ICAL_COMPONENT> pcomponent, APPOINTMENTRECURRENCEPATTERN *papprecurr)
{
	ICAL_TIME itime;
	time_t unix_time;
	uint64_t nt_time;
	const char *str_tag;
	std::shared_ptr<ICAL_VALUE> pivalue;
	char tmp_buff[1024];
	
	str_tag = NULL;
	switch (papprecurr->recurrencepattern.calendartype) {
	case CALENDARTYPE_DEFAULT:
		switch (papprecurr->recurrencepattern.patterntype) {
		case PATTERNTYPE_HJMONTH:
		case PATTERNTYPE_HJMONTHNTH:
			str_tag = "X-MICROSOFT-RRULE";
			break;
		default:
			str_tag = "RRULE";
			break;
		}
		break;
	case CALENDARTYPE_GREGORIAN:
	case CALENDARTYPE_GREGORIAN_US:
	case CALENDARTYPE_JAPAN:
	case CALENDARTYPE_TAIWAN:
	case CALENDARTYPE_KOREA:
		str_tag = "RRULE";
		break;
	case CALENDARTYPE_HIJRI:
		str_tag = "X-MICROSOFT-RRULE";
		break;
	case CALENDARTYPE_THAI:
		str_tag = "RRULE";
		break;
	case CALENDARTYPE_HEBREW:
		str_tag = "X-MICROSOFT-RRULE";
		break;
	case CALENDARTYPE_GREGORIAN_ME_FRENCH:
	case CALENDARTYPE_GREGORIAN_ARABIC:
	case CALENDARTYPE_GREGORIAN_XLIT_ENGLISH:
	case CALENDARTYPE_GREGORIAN_XLIT_FRENCH:
		str_tag = "RRULE";
		break;
	case CALENDARTYPE_LUNAR_JAPANESE:
	case CALENDARTYPE_CHINESE_LUNAR:
	case CALENDARTYPE_SAKA:
	case CALENDARTYPE_LUNAR_ETO_CHN:
	case CALENDARTYPE_LUNAR_ETO_KOR:
	case CALENDARTYPE_LUNAR_ETO_ROKUYOU:
	case CALENDARTYPE_LUNAR_KOREAN:
	case CALENDARTYPE_UMALQURA:
		str_tag = "X-MICROSOFT-RRULE";
		break;
	}
	if (NULL == str_tag) {
		return FALSE;
	}
	auto piline = ical_new_line(str_tag);
	if (NULL == piline) {
		return FALSE;
	}
	if (pcomponent->append_line(piline) < 0)
		return false;
	switch (papprecurr->recurrencepattern.patterntype) {
	case PATTERNTYPE_DAY:
		pivalue = ical_new_value("FREQ");
		if (NULL == pivalue) {
			return FALSE;
		}
		if (piline->append_value(pivalue) < 0)
			return false;
		if (!pivalue->append_subval("DAILY"))
			return FALSE;
		sprintf(tmp_buff, "%u",
			papprecurr->recurrencepattern.period/1440);
		pivalue = ical_new_value("INTERVAL");
		if (NULL == pivalue) {
			return FALSE;
		}
		if (piline->append_value(pivalue) < 0)
			return false;
		if (!pivalue->append_subval(tmp_buff))
			return FALSE;
		break;
	case PATTERNTYPE_WEEK:
		pivalue = ical_new_value("FREQ");
		if (NULL == pivalue) {
			return FALSE;
		}
		if (piline->append_value(pivalue) < 0)
			return false;
		if (!pivalue->append_subval("WEEKLY"))
			return FALSE;
		sprintf(tmp_buff, "%u",
			papprecurr->recurrencepattern.period);
		pivalue = ical_new_value("INTERVAL");
		if (NULL == pivalue) {
			return FALSE;
		}
		if (piline->append_value(pivalue) < 0)
			return false;
		if (!pivalue->append_subval(tmp_buff))
			return FALSE;
		pivalue = ical_new_value("BYDAY");
		if (NULL == pivalue) {
			return FALSE;
		}
		if (piline->append_value(pivalue) < 0)
			return false;
		if (WEEKRECURRENCEPATTERN_SU&
			papprecurr->recurrencepattern.
			patterntypespecific.weekrecurrence) {
			if (!pivalue->append_subval("SU"))
				return FALSE;
		}
		if (WEEKRECURRENCEPATTERN_M&
			papprecurr->recurrencepattern.
			patterntypespecific.weekrecurrence) {
			if (!pivalue->append_subval("MO"))
				return FALSE;
		}
		if (WEEKRECURRENCEPATTERN_TU&
			papprecurr->recurrencepattern.
			patterntypespecific.weekrecurrence) {
			if (!pivalue->append_subval("TU"))
				return FALSE;
		}
		if (WEEKRECURRENCEPATTERN_W&
			papprecurr->recurrencepattern.
			patterntypespecific.weekrecurrence) {
			if (!pivalue->append_subval("WE"))
				return FALSE;
		}
		if (WEEKRECURRENCEPATTERN_TH&
			papprecurr->recurrencepattern.
			patterntypespecific.weekrecurrence) {
			if (!pivalue->append_subval("TH"))
				return FALSE;
		}
		if (WEEKRECURRENCEPATTERN_F&
			papprecurr->recurrencepattern.
			patterntypespecific.weekrecurrence) {
			if (!pivalue->append_subval("FR"))
				return FALSE;
		}
		if (WEEKRECURRENCEPATTERN_SA&
			papprecurr->recurrencepattern.
			patterntypespecific.weekrecurrence) {
			if (!pivalue->append_subval("SA"))
				return FALSE;
		}
		break;
	case PATTERNTYPE_MONTH:
	case PATTERNTYPE_HJMONTH:
		pivalue = ical_new_value("FREQ");
		if (NULL == pivalue) {
			return FALSE;
		}
		if (piline->append_value(pivalue) < 0)
			return false;
		if (0 != papprecurr->recurrencepattern.period%12) {
			if (!pivalue->append_subval("MONTHLY"))
				return FALSE;
			sprintf(tmp_buff, "%u",
				papprecurr->recurrencepattern.period);
			pivalue = ical_new_value("INTERVAL");
			if (NULL == pivalue) {
				return FALSE;
			}
			if (piline->append_value(pivalue) < 0)
				return false;
			if (!pivalue->append_subval(tmp_buff))
				return FALSE;
			pivalue = ical_new_value("BYMONTHDAY");
			if (NULL == pivalue) {
				return FALSE;
			}
			if (piline->append_value(pivalue) < 0)
				return false;
			if (31 == papprecurr->recurrencepattern.
				patterntypespecific.dayofmonth) {
				strcpy(tmp_buff, "-1");
			} else {
				sprintf(tmp_buff, "%u",
					papprecurr->recurrencepattern.
					patterntypespecific.dayofmonth);
			}
			if (!pivalue->append_subval(tmp_buff))
				return FALSE;
		} else {
			if (!pivalue->append_subval("YEARLY"))
				return FALSE;
			sprintf(tmp_buff, "%u",
				papprecurr->recurrencepattern.period/12);
			pivalue = ical_new_value("INTERVAL");
			if (NULL == pivalue) {
				return FALSE;
			}
			if (piline->append_value(pivalue) < 0)
				return false;
			if (!pivalue->append_subval(tmp_buff))
				return FALSE;
			pivalue = ical_new_value("BYMONTHDAY");
			if (NULL == pivalue) {
				return FALSE;
			}
			if (piline->append_value(pivalue) < 0)
				return false;
			if (31 == papprecurr->recurrencepattern.
				patterntypespecific.dayofmonth) {
				strcpy(tmp_buff, "-1");
			} else {
				sprintf(tmp_buff, "%u",
					papprecurr->recurrencepattern.
					patterntypespecific.dayofmonth);
			}
			if (!pivalue->append_subval(tmp_buff))
				return FALSE;
			pivalue = ical_new_value("BYMONTH");
			if (NULL == pivalue) {
				return FALSE;
			}
			if (piline->append_value(pivalue) < 0)
				return false;
			ical_get_itime_from_yearday(1601, 
				papprecurr->recurrencepattern.firstdatetime/
				1440 + 1, &itime);
			sprintf(tmp_buff, "%u", itime.month);
			if (!pivalue->append_subval(tmp_buff))
				return FALSE;
		}
		break;
	case PATTERNTYPE_MONTHNTH:
	case PATTERNTYPE_HJMONTHNTH:
		pivalue = ical_new_value("FREQ");
		if (NULL == pivalue) {
			return FALSE;
		}
		if (piline->append_value(pivalue) < 0)
			return false;
		if (0 != papprecurr->recurrencepattern.period%12) {
			if (!pivalue->append_subval("MONTHLY"))
				return FALSE;
			sprintf(tmp_buff, "%u",
				papprecurr->recurrencepattern.period);
			pivalue = ical_new_value("INTERVAL");
			if (NULL == pivalue) {
				return FALSE;
			}
			if (piline->append_value(pivalue) < 0)
				return false;
			if (!pivalue->append_subval(tmp_buff))
				return FALSE;
			pivalue = ical_new_value("BYDAY");
			if (NULL == pivalue) {
				return FALSE;
			}
			if (piline->append_value(pivalue) < 0)
				return false;
			if (WEEKRECURRENCEPATTERN_SU&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (!pivalue->append_subval("SU"))
					return FALSE;
			}
			if (WEEKRECURRENCEPATTERN_M&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (!pivalue->append_subval("MO"))
					return FALSE;
			}
			if (WEEKRECURRENCEPATTERN_TU&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (!pivalue->append_subval("TU"))
					return FALSE;
			}
			if (WEEKRECURRENCEPATTERN_W&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (!pivalue->append_subval("WE"))
					return FALSE;
			}
			if (WEEKRECURRENCEPATTERN_TH&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (!pivalue->append_subval("TH"))
					return FALSE;
			}
			if (WEEKRECURRENCEPATTERN_F&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (!pivalue->append_subval("FR"))
					return FALSE;
			}
			if (WEEKRECURRENCEPATTERN_SA&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (!pivalue->append_subval("SA"))
					return FALSE;
			}
			pivalue = ical_new_value("BYSETPOS");
			if (NULL == pivalue) {
				return FALSE;
			}
			if (piline->append_value(pivalue) < 0)
				return false;
			if (5 == papprecurr->recurrencepattern.
				patterntypespecific.monthnth.recurrencenum) {
				strcpy(tmp_buff, "-1");
			} else {
				sprintf(tmp_buff, "%u",
					papprecurr->recurrencepattern.
					patterntypespecific.monthnth.recurrencenum);
			}
			if (!pivalue->append_subval(tmp_buff))
				return FALSE;
		} else {
			if (!pivalue->append_subval("YEARLY"))
				return FALSE;
			sprintf(tmp_buff, "%u",
				papprecurr->recurrencepattern.period/12);
			pivalue = ical_new_value("INTERVAL");
			if (NULL == pivalue) {
				return FALSE;
			}
			if (piline->append_value(pivalue) < 0)
				return false;
			if (!pivalue->append_subval(tmp_buff))
				return FALSE;
			pivalue = ical_new_value("BYDAY");
			if (NULL == pivalue) {
				return FALSE;
			}
			if (piline->append_value(pivalue) < 0)
				return false;
			if (WEEKRECURRENCEPATTERN_SU&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (!pivalue->append_subval("SU"))
					return FALSE;
			}
			if (WEEKRECURRENCEPATTERN_M&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (!pivalue->append_subval("MO"))
					return FALSE;
			}
			if (WEEKRECURRENCEPATTERN_TU&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (!pivalue->append_subval("TU"))
					return FALSE;
			}
			if (WEEKRECURRENCEPATTERN_W&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (!pivalue->append_subval("WE"))
					return FALSE;
			}
			if (WEEKRECURRENCEPATTERN_TH&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (!pivalue->append_subval("TH"))
					return FALSE;
			}
			if (WEEKRECURRENCEPATTERN_F&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (!pivalue->append_subval("FR"))
					return FALSE;
			}
			if (WEEKRECURRENCEPATTERN_SA&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (!pivalue->append_subval("SA"))
					return FALSE;
			}
			pivalue = ical_new_value("BYSETPOS");
			if (NULL == pivalue) {
				return FALSE;
			}
			if (piline->append_value(pivalue) < 0)
				return false;
			if (5 == papprecurr->recurrencepattern.
				patterntypespecific.monthnth.recurrencenum) {
				strcpy(tmp_buff, "-1");
			} else {
				sprintf(tmp_buff, "%u",
					papprecurr->recurrencepattern.
					patterntypespecific.monthnth.recurrencenum);
			}
			if (!pivalue->append_subval(tmp_buff))
				return FALSE;
			pivalue = ical_new_value("BYMONTH");
			if (NULL == pivalue) {
				return FALSE;
			}
			if (piline->append_value(pivalue) < 0)
				return false;
			sprintf(tmp_buff, "%u",
				papprecurr->recurrencepattern.firstdatetime);
			if (!pivalue->append_subval(tmp_buff))
				return FALSE;
		}
		break;
	default:
		return FALSE;
	}
	if (ENDTYPE_AFTER_N_OCCURRENCES ==
		papprecurr->recurrencepattern.endtype) {
		sprintf(tmp_buff, "%u",
			papprecurr->recurrencepattern.occurrencecount);
		pivalue = ical_new_value("COUNT");
		if (NULL == pivalue) {
			return FALSE;
		}
		if (piline->append_value(pivalue) < 0)
			return false;
		if (!pivalue->append_subval(tmp_buff))
			return FALSE;
	} else if (ENDTYPE_AFTER_DATE ==
		papprecurr->recurrencepattern.endtype) {
		nt_time = papprecurr->recurrencepattern.enddate
						+ papprecurr->starttimeoffset;
		nt_time *= 600000000;
		unix_time = rop_util_nttime_to_unix(nt_time);
		ical_utc_to_datetime(NULL, unix_time, &itime);
		if (!ical_itime_to_utc(ptz_component, itime, &unix_time))
			return FALSE;
		ical_utc_to_datetime(NULL, unix_time, &itime);
		sprintf(tmp_buff, "%04d%02d%02dT%02d%02d%02dZ",
			itime.year, itime.month, itime.day,
			itime.hour, itime.minute, itime.second);
		pivalue = ical_new_value("UNTIL");
		if (NULL == pivalue) {
			return FALSE;
		}
		if (piline->append_value(pivalue) < 0)
			return false;
		if (!pivalue->append_subval(tmp_buff))
			return FALSE;
	}
	if (PATTERNTYPE_WEEK == papprecurr->recurrencepattern.patterntype) {
		pivalue = ical_new_value("WKST");
		if (NULL == pivalue) {
			return FALSE;
		}
		if (piline->append_value(pivalue) < 0)
			return false;
		switch (papprecurr->recurrencepattern.firstdow) {
		case 0:
			if (!pivalue->append_subval("SU"))
				return FALSE;
			break;
		case 1:
			if (!pivalue->append_subval("MO"))
				return FALSE;
			break;
		case 2:
			if (!pivalue->append_subval("TU"))
				return FALSE;
			break;
		case 3:
			if (!pivalue->append_subval("WE"))
				return FALSE;
			break;
		case 4:
			if (!pivalue->append_subval("TH"))
				return FALSE;
			break;
		case 5:
			if (!pivalue->append_subval("FR"))
				return FALSE;
			break;
		case 6:
			if (!pivalue->append_subval("SA"))
				return FALSE;
			break;
		default:
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL oxcical_check_exdate(
	APPOINTMENTRECURRENCEPATTERN *papprecurr)
{
	int i, j;
	int count;
	BOOL b_found;
	
	count = 0;
	for (i=0; i<papprecurr->recurrencepattern.deletedinstancecount; i++) {
		b_found = FALSE;
		for (j=0; j<papprecurr->exceptioncount; j++) {
			if (papprecurr->recurrencepattern.pdeletedinstancedates[i]
				== papprecurr->pexceptioninfo[j].originalstartdate &&
				0 != papprecurr->pexceptioninfo[j].overrideflags) {
				b_found = TRUE;
				break;
			}
		}
		if (FALSE == b_found) {
			count ++;
		}
	}
	if (0 == count) {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_export_exdate(const char *tzid, BOOL b_date,
    std::shared_ptr<ICAL_COMPONENT> pcomponent,
	APPOINTMENTRECURRENCEPATTERN *papprecurr)
{
	int i, j;
	BOOL b_found;
	time_t tmp_time;
	ICAL_TIME itime;
	std::shared_ptr<ICAL_LINE> piline;
	uint64_t tmp_int64;
	std::shared_ptr<ICAL_PARAM> piparam;
	char tmp_buff[1024];
	
	if (CALENDARTYPE_DEFAULT !=
		papprecurr->recurrencepattern.calendartype ||
		PATTERNTYPE_HJMONTH ==
		papprecurr->recurrencepattern.patterntype ||
		PATTERNTYPE_HJMONTHNTH ==
		papprecurr->recurrencepattern.patterntype) {
		piline = ical_new_line("X-MICROSOFT-EXDATE");
	} else {
		piline = ical_new_line("EXDATE");
	}
	if (NULL == piline) {
		return FALSE;
	}
	if (pcomponent->append_line(piline) < 0)
		return false;
	auto pivalue = ical_new_value(nullptr);
	if (NULL == pivalue) {
		return FALSE;
	}
	if (piline->append_value(pivalue) < 0)
		return false;
	if (TRUE == b_date) {
		piparam = ical_new_param("VALUE");
		if (NULL == piparam) {
			return FALSE;
		}
		if (piline->append_param(piparam) < 0)
			return false;
		if (!piparam->append_paramval("DATE"))
			return FALSE;
	} else {
		if (NULL != tzid) {
			piparam = ical_new_param("TZID");
			if (NULL == piparam) {
				return FALSE;
			}
			if (piline->append_param(piparam) < 0)
				return false;
			if (!piparam->append_paramval(tzid))
				return FALSE;
		}
	}
	for (i=0; i<papprecurr->recurrencepattern.deletedinstancecount; i++) {
		b_found = FALSE;
		for (j=0; j<papprecurr->exceptioncount; j++) {
			if (papprecurr->recurrencepattern.pdeletedinstancedates[i]
				== papprecurr->pexceptioninfo[j].originalstartdate &&
				0 != papprecurr->pexceptioninfo[j].overrideflags) {
				b_found = TRUE;
				break;
			}
		}
		if (TRUE == b_found) {
			continue;
		}
		tmp_int64 = (papprecurr->recurrencepattern.pdeletedinstancedates[i]
								+ papprecurr->starttimeoffset) *600000000;
		tmp_time = rop_util_nttime_to_unix(tmp_int64);
		ical_utc_to_datetime(NULL, tmp_time, &itime);
		if (TRUE == b_date) {
			sprintf(tmp_buff, "%04d%02d%02d",
				itime.year, itime.month, itime.day);
		} else {
			if (NULL == tzid) {
				sprintf(tmp_buff, "%04d%02d%02dT%02d%02d%02dZ",
							itime.year, itime.month, itime.day,
							itime.hour, itime.minute, itime.second);
			} else {
				sprintf(tmp_buff, "%04d%02d%02dT%02d%02d%02d",
							itime.year, itime.month, itime.day,
							itime.hour, itime.minute, itime.second);
			}
		}
		if (!pivalue->append_subval(tmp_buff))
			return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_check_rdate(
	APPOINTMENTRECURRENCEPATTERN *papprecurr)
{
	int i, j;
	int count;
	BOOL b_found;
	
	count = 0;
	for (i=0; i<papprecurr->recurrencepattern.modifiedinstancecount; i++) {
		b_found = FALSE;
		for (j=0; j<papprecurr->exceptioncount; j++) {
			if (papprecurr->recurrencepattern.pmodifiedinstancedates[i]
				== papprecurr->pexceptioninfo[j].startdatetime &&
				0 != papprecurr->pexceptioninfo[j].overrideflags) {
				b_found = TRUE;
				break;
			}
		}
		if (FALSE == b_found) {
			count ++;
		}
	}
	if (0 == count) {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_export_rdate(const char *tzid, BOOL b_date,
     std::shared_ptr<ICAL_COMPONENT> pcomponent,
	APPOINTMENTRECURRENCEPATTERN *papprecurr)
{
	int i, j;
	BOOL b_found;
	time_t tmp_time;
	ICAL_TIME itime;
	uint64_t tmp_int64;
	std::shared_ptr<ICAL_PARAM> piparam;
	char tmp_buff[1024];
	
	auto piline = ical_new_line("RDATE");
	if (NULL == piline) {
		return FALSE;
	}
	if (pcomponent->append_line(piline) < 0)
		return false;
	auto pivalue = ical_new_value(nullptr);
	if (NULL == pivalue) {
		return FALSE;
	}
	if (piline->append_value(pivalue) < 0)
		return false;
	if (TRUE == b_date) {
		piparam = ical_new_param("VALUE");
		if (NULL == piparam) {
			return FALSE;
		}
		if (piline->append_param(piparam) < 0)
			return false;
		if (!piparam->append_paramval("DATE"))
			return FALSE;
	} else {
		if (NULL != tzid) {
			piparam = ical_new_param("TZID");
			if (NULL == piparam) {
				return FALSE;
			}
			if (piline->append_param(piparam) < 0)
				return false;
			if (!piparam->append_paramval(tzid))
				return FALSE;
		}
	}
	for (i=0; i<papprecurr->recurrencepattern.deletedinstancecount; i++) {
		b_found = FALSE;
		for (j=0; j<papprecurr->exceptioncount; j++) {
			if (papprecurr->recurrencepattern.pmodifiedinstancedates[i]
				== papprecurr->pexceptioninfo[j].startdatetime &&
				0 != papprecurr->pexceptioninfo[j].overrideflags) {
				b_found = TRUE;
				break;
			}
		}
		if (TRUE == b_found) {
			continue;
		}
		tmp_int64 = papprecurr->recurrencepattern.
				pmodifiedinstancedates[i]*600000000;
		tmp_time = rop_util_nttime_to_unix(tmp_int64);
		ical_utc_to_datetime(NULL, tmp_time, &itime);
		if (TRUE == b_date) {
			sprintf(tmp_buff, "%04d%02d%02d",
				itime.year, itime.month, itime.day);
		} else {
			if (NULL == tzid) {
				sprintf(tmp_buff, "%04d%02d%02dT%02d%02d%02dZ",
							itime.year, itime.month, itime.day,
							itime.hour, itime.minute, itime.second);
			} else {
				sprintf(tmp_buff, "%04d%02d%02dT%02d%02d%02d",
							itime.year, itime.month, itime.day,
							itime.hour, itime.minute, itime.second);
			}
		}
		if (!pivalue->append_subval(tmp_buff))
			return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_export_internal(const char *method, const char *tzid,
    std::shared_ptr<ICAL_COMPONENT> ptz_component, MESSAGE_CONTENT *pmsg,
    ICAL *pical, ENTRYID_TO_USERNAME entryid_to_username,
	ESSDN_TO_USERNAME essdn_to_username,
	LCID_TO_LTAG lcid_to_ltag, EXT_BUFFER_ALLOC alloc,
	GET_PROPIDS get_propids)
{
	int i;
	int year;
	GUID guid;
	void *pvalue;
	uint32_t lid;
	BOOL b_allday;
	time_t cur_time;
	time_t end_time;
	ICAL_TIME itime;
	BOOL b_proposal;
	uint32_t proptag;
	struct tm tmp_tm;
	EXT_PULL ext_pull;
	EXT_PUSH ext_push;
	BOOL b_recurrence;
	time_t start_time;
	BOOL b_exceptional;
	std::shared_ptr<ICAL_VALUE> pivalue;
	std::shared_ptr<ICAL_PARAM> piparam;
	char tmp_buff[1024];
	char tmp_buff1[2048];
	uint32_t proptag_xrt;
	PROPID_ARRAY propids;
	const char *partstat;
	const char *str_value;
	const char *planguage;
	PROPERTY_NAME propname;
	PROPNAME_ARRAY propnames;
	TIMEZONESTRUCT tz_struct;
	MESSAGE_CONTENT *pembedded;
	GLOBALOBJECTID globalobjectid;
	TIMEZONEDEFINITION tz_definition;
	APPOINTMENTRECURRENCEPATTERN apprecurr;
	
	
	propnames.count = 1;
	propnames.ppropname = &propname;
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_MESSAGELOCALEID);
	if (NULL == pvalue) {
		planguage = NULL;
	} else {
		planguage = lcid_to_ltag(*(uint32_t*)pvalue);
	}
	
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_MESSAGECLASS);
	if (NULL == pvalue) {
		pvalue = tpropval_array_get_propval(
			&pmsg->proplist, PROP_TAG_MESSAGECLASS_STRING8);
	}
	if (NULL == pvalue) {
		return FALSE;
	}
	partstat = NULL;
	b_proposal = FALSE;
	if (NULL != method) {
		b_exceptional = TRUE;
	} else {
		b_exceptional = FALSE;
		if (strcasecmp(static_cast<char *>(pvalue), "IPM.Appointment") == 0) {
			method = "PUBLISH";
		} else if (strcasecmp(static_cast<char *>(pvalue), "IPM.Schedule.Meeting.Request") == 0) {
			method = "REQUEST";
			partstat = "NEEDS-ACTION";
		} else if (strcasecmp(static_cast<char *>(pvalue), "IPM.Schedule.Meeting.Resp.Pos") == 0) {
			method = "REPLY";
			partstat = "ACCEPTED";
		} else if (strcasecmp(static_cast<char *>(pvalue), "IPM.Schedule.Meeting.Resp.Tent") == 0) {
			partstat = "TENTATIVE";
			propname.kind = MNID_ID;
			propname.plid = &lid;
			rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
			/* PidLidAppointmentCounterProposal */
			lid = 0x00008257;
			if (FALSE == get_propids(&propnames, &propids)) {
				return FALSE;
			}
			proptag = PROP_TAG(PT_BOOLEAN, propids.ppropid[0]);
			pvalue = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
			if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
				b_proposal = TRUE;
				method = "COUNTER";
			} else {
				method = "REPLY";
			}
		} else if (strcasecmp(static_cast<char *>(pvalue), "IPM.Schedule.Meeting.Resp.Neg") == 0) {
			method = "REPLY";
			partstat = "DECLINED";
		} else if (strcasecmp(static_cast<char *>(pvalue), "IPM.Schedule.Meeting.Canceled") == 0) {
			method = "CANCEL";
			partstat = "NEEDS-ACTION";
		} else {
			return FALSE;
		}
	}
	propname.kind = MNID_ID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	if (TRUE == b_proposal) {
		/* PidLidAppointmentProposedStartWhole */
		lid = 0x00008250;
	} else {
		/* PidLidAppointmentStartWhole */
		lid = 0x0000820D;
	}
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = PROP_TAG(PT_SYSTIME, propids.ppropid[0]);
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, proptag);
	if (NULL == pvalue) {
		return FALSE;
	}
	start_time = rop_util_nttime_to_unix(*(uint64_t*)pvalue);
	
	propname.kind = MNID_ID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	if (TRUE == b_proposal) {
		/* PidLidAppointmentProposedEndWhole */
		lid = 0x00008251;
	} else {
		/* PidLidAppointmentEndWhole */
		lid = 0x0000820E;
	}
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = PROP_TAG(PT_SYSTIME, propids.ppropid[0]);
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, proptag);
	if (NULL != pvalue) {
		end_time = rop_util_nttime_to_unix(*(uint64_t*)pvalue);
	} else {
		/* PidLidAppointmentDuration */
		lid = 0x00008213;
		if (FALSE == get_propids(&propnames, &propids)) {
			return FALSE;
		}
		proptag = PROP_TAG(PT_LONG, propids.ppropid[0]);
		pvalue = tpropval_array_get_propval(
			&pmsg->proplist, proptag);
		if (NULL == pvalue) {
			end_time = start_time;
		} else {
			end_time = start_time + *(uint32_t*)pvalue;
		}
	}
	
	std::shared_ptr<ICAL_LINE> piline;
	if (TRUE == b_exceptional) {
		goto EXPORT_VEVENT;
	}
	
	piline = ical_new_simple_line("METHOD", method);
	if (NULL == piline) {
		return FALSE;
	}
	if (pical->append_line(piline) < 0)
		return false;
	piline = ical_new_simple_line("PRODID", "gromox-oxical");
	if (NULL == piline) {
		return FALSE;
	}
	if (pical->append_line(piline) < 0)
		return false;
	
	piline = ical_new_simple_line("VERSION", "2.0");
	if (NULL == piline) {
		return FALSE;
	}
	if (pical->append_line(piline) < 0)
		return false;
	
	propname.kind = MNID_ID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	/* PidLidAppointmentRecur */
	lid = 0x00008216;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = PROP_TAG(PT_BINARY, propids.ppropid[0]);
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, proptag);
	if (NULL == pvalue) {
		b_recurrence = FALSE;
	} else {
		ext_buffer_pull_init(&ext_pull, ((BINARY*)pvalue)->pb,
			((BINARY*)pvalue)->cb, alloc, EXT_FLAG_UTF16);
		if (EXT_ERR_SUCCESS != ext_buffer_pull_appointmentrecurrencepattern(
			&ext_pull, &apprecurr)) {
			return FALSE;
		}
		b_recurrence = TRUE;
	}
	
	if (TRUE == b_recurrence) {
		switch (apprecurr.recurrencepattern.calendartype) {
		case CALENDARTYPE_GREGORIAN:
			str_value = "Gregorian";
			break;
		case CALENDARTYPE_GREGORIAN_US:
			str_value = "Gregorian_us";
			break;
		case CALENDARTYPE_JAPAN:
			str_value = "Japan";
			break;
		case CALENDARTYPE_TAIWAN:
			str_value = "Taiwan";
			break;
		case CALENDARTYPE_KOREA:
			str_value = "Korea";
			break;
		case CALENDARTYPE_HIJRI:
			str_value = "Hijri";
			break;
		case CALENDARTYPE_THAI:
			str_value = "Thai";
			break;
		case CALENDARTYPE_HEBREW:
			str_value = "Hebrew";
			break;
		case CALENDARTYPE_GREGORIAN_ME_FRENCH:
			str_value = "GregorianMeFrench";
			break;
		case CALENDARTYPE_GREGORIAN_ARABIC:
			str_value = "GregorianArabic";
			break;
		case CALENDARTYPE_GREGORIAN_XLIT_ENGLISH:
			str_value = "GregorianXlitEnglish";
			break;
		case CALENDARTYPE_GREGORIAN_XLIT_FRENCH:
			str_value = "GregorianXlitFrench";
			break;
		case CALENDARTYPE_LUNAR_JAPANESE:
			str_value = "JapanLunar";
			break;
		case CALENDARTYPE_CHINESE_LUNAR:
			str_value = "ChineseLunar";
			break;
		case CALENDARTYPE_SAKA:
			str_value = "Saka";
			break;
		case CALENDARTYPE_LUNAR_ETO_CHN:
			str_value = "LunarEtoChn";
			break;
		case CALENDARTYPE_LUNAR_ETO_KOR:
			str_value = "LunarEtoKor";
			break;
		case CALENDARTYPE_LUNAR_ETO_ROKUYOU:
			str_value = "LunaRokuyou";
			break;
		case CALENDARTYPE_LUNAR_KOREAN:
			str_value = "KoreaLunar";
			break;
		case CALENDARTYPE_UMALQURA:
			str_value = "Umalqura";
			break;
		default:
			str_value = NULL;
		}
		if (PATTERNTYPE_HJMONTH ==
			apprecurr.recurrencepattern.patterntype ||
			PATTERNTYPE_HJMONTHNTH ==
			apprecurr.recurrencepattern.patterntype) {
			str_value = "Hijri";
		}
		if (NULL != str_value) {
			piline = ical_new_simple_line(
				"X-MICROSOFT-CALSCALE", str_value);
			if (NULL == piline) {
				return FALSE;
			}
			if (const_cast<ICAL *>(pical)->append_line(piline) < 0)
				return false;
		}
	}
	
	make_gmtm(start_time, &tmp_tm);
	year = tmp_tm.tm_year + 1900;
	
	tzid = NULL;
	ptz_component = NULL;
	if (TRUE == b_recurrence) {
		propname.kind = MNID_ID;
		propname.plid = &lid;
		rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
		/* PidLidTimeZoneStruct */
		lid = 0x00008233;
		if (FALSE == get_propids(&propnames, &propids)) {
			return FALSE;
		}
		proptag = PROP_TAG(PT_BINARY, propids.ppropid[0]);
		pvalue = tpropval_array_get_propval(
			&pmsg->proplist, proptag);
		if (NULL != pvalue) {
			propname.kind = MNID_ID;
			propname.plid = &lid;
			rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
			/* PidLidTimeZoneDescription */
			lid = 0x00008234;
			if (FALSE == get_propids(&propnames, &propids)) {
				return FALSE;
			}
			proptag = PROP_TAG(PT_UNICODE, propids.ppropid[0]);
			tzid = static_cast<char *>(tpropval_array_get_propval(
			       &pmsg->proplist, proptag));
			if (NULL == tzid) {
				goto EXPORT_TZDEFINITION;
			}
			ext_buffer_pull_init(&ext_pull, ((BINARY*)pvalue)->pb,
			((BINARY*)pvalue)->cb, alloc, 0);
			if (EXT_ERR_SUCCESS != ext_buffer_pull_timezonestruct(
				&ext_pull, &tz_struct)) {
				return FALSE;
			}
			ptz_component = oxcical_export_timezone(
					pical, year - 1, tzid, &tz_struct);
			if (NULL == ptz_component) {
				return FALSE;
			}
		} else {
 EXPORT_TZDEFINITION:
			propname.kind = MNID_ID;
			propname.plid = &lid;
			rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
			/* PidLidAppointmentTimeZoneDefinitionRecur */
			lid = 0x00008260;
			if (FALSE == get_propids(&propnames, &propids)) {
				return FALSE;
			}
			proptag = PROP_TAG(PT_BINARY, propids.ppropid[0]);
			pvalue = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
			if (NULL != pvalue) {
				ext_buffer_pull_init(&ext_pull, ((BINARY*)pvalue)->pb,
				((BINARY*)pvalue)->cb, alloc, 0);
				if (EXT_ERR_SUCCESS != ext_buffer_pull_timezonedefinition(
					&ext_pull, &tz_definition)) {
					return FALSE;
				}
				tzid = tz_definition.keyname;
				oxcical_convert_to_tzstruct(&tz_definition, &tz_struct);
				ptz_component = oxcical_export_timezone(
						pical, year - 1, tzid, &tz_struct);
				if (NULL == ptz_component) {
					return FALSE;
				}
			}
		}
	} else {
		propname.kind = MNID_ID;
		propname.plid = &lid;
		rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
		/* PidLidAppointmentTimeZoneDefinitionStartDisplay */
		lid = 0x0000825E;
		if (FALSE == get_propids(&propnames, &propids)) {
			return FALSE;
		}
		proptag = PROP_TAG(PT_BINARY, propids.ppropid[0]);
		pvalue = tpropval_array_get_propval(
			&pmsg->proplist, proptag);
		if (NULL != pvalue) {
			/* PidLidAppointmentTimeZoneDefinitionEndDisplay */
			lid = 0x0000825F;
			if (FALSE == get_propids(&propnames, &propids)) {
				return FALSE;
			}
			proptag = PROP_TAG(PT_BINARY, propids.ppropid[0]);
			pvalue = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
		}
		if (NULL != pvalue) {
			ext_buffer_pull_init(&ext_pull, ((BINARY*)pvalue)->pb,
								((BINARY*)pvalue)->cb, alloc, 0);
			if (EXT_ERR_SUCCESS != ext_buffer_pull_timezonedefinition(
				&ext_pull, &tz_definition)) {
				return FALSE;
			}
			tzid = tz_definition.keyname;
			oxcical_convert_to_tzstruct(&tz_definition, &tz_struct);
			ptz_component = oxcical_export_timezone(
					pical, year - 1, tzid, &tz_struct);
			if (NULL == ptz_component) {
				return FALSE;
			}
		}
	}
	
 EXPORT_VEVENT:
	propname.kind = MNID_ID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	/* PidLidAppointmentSubType */
	lid = 0x00008215;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = PROP_TAG(PT_BOOLEAN, propids.ppropid[0]);
	pvalue = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		b_allday = TRUE;
	} else {
		b_allday = FALSE;
	}

	auto pcomponent = ical_new_component("VEVENT");
	if (NULL == pcomponent) {
		return FALSE;
	}
	pical->append_comp(pcomponent);
	
	if (0 == strcmp(method, "REQUEST") ||
		0 == strcmp(method, "CANCEL")) {
		pvalue = tpropval_array_get_propval(&pmsg->proplist,
					PROP_TAG_SENTREPRESENTINGSMTPADDRESS);
		if (NULL != pvalue) {
			pvalue = tpropval_array_get_propval(&pmsg->proplist,
						PROP_TAG_SENTREPRESENTINGADDRESSTYPE);
			if (pvalue != NULL) {
				if (strcasecmp(static_cast<char *>(pvalue), "SMTP") == 0) {
					pvalue = tpropval_array_get_propval(&pmsg->proplist,
								PROP_TAG_SENTREPRESENTINGEMAILADDRESS);
				} else if (strcasecmp(static_cast<char *>(pvalue), "EX") == 0) {
					pvalue = tpropval_array_get_propval(&pmsg->proplist,
								PROP_TAG_SENTREPRESENTINGEMAILADDRESS);
					if (NULL != pvalue) {
						pvalue = !essdn_to_username(static_cast<char *>(pvalue), tmp_buff) ?
						         nullptr : tmp_buff;
					}
				} else {
					pvalue = NULL;
				}
			}
		}
		if (NULL != pvalue) {
			snprintf(tmp_buff1, sizeof(tmp_buff1), "MAILTO:%s",
			         static_cast<const char *>(pvalue));
			piline = ical_new_simple_line("ORGANIZER", tmp_buff1);
			if (NULL == piline) {
				return FALSE;
			}
			if (pcomponent->append_line(piline) < 0)
				return false;
			pvalue = tpropval_array_get_propval(&pmsg->proplist,
							PROP_TAG_SENTREPRESENTINGNAME);
			if (NULL != pvalue) {
				piparam = ical_new_param("CN");
				if (NULL == piparam) {
					return FALSE;
				}
				if (piline->append_param(piparam) < 0)
					return false;
				if (!piparam->append_paramval(static_cast<char *>(pvalue)))
					return FALSE;
			}
		}
	}
	
	if (FALSE == oxcical_export_recipient_table(
		pcomponent, entryid_to_username,
		essdn_to_username, alloc, partstat,
		(MESSAGE_CONTENT*)pmsg)) {
		return FALSE;
	}
	
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_BODY);
	if (NULL != pvalue) {
		if (0 == strcmp(method, "REPLY") ||
			0 == strcmp(method, "COUNTER")) {
			piline = ical_new_simple_line("COMMENT", static_cast<char *>(pvalue));
		} else {
			piline = ical_new_simple_line("DESCRIPTION", static_cast<char *>(pvalue));
		}
		if (NULL == piline) {
			return FALSE;
		}
		if (pcomponent->append_line(piline) < 0)
			return false;
		if (NULL != planguage) {
			piparam = ical_new_param("LANGUAGE");
			if (NULL == piparam) {
				return FALSE;
			}
			if (piline->append_param(piparam) < 0)
				return false;
			if (!piparam->append_paramval(planguage))
				return FALSE;
		}
	}
	
	if (FALSE == b_exceptional && TRUE == b_recurrence) {
		if (FALSE == oxcical_export_rrule(
			ptz_component, pcomponent, &apprecurr)) {
			return FALSE;
		}
		if (TRUE == oxcical_check_exdate(&apprecurr)) {
			if (FALSE == oxcical_export_exdate(tzid,
				b_allday, pcomponent, &apprecurr)) {
				return FALSE;
			}
		}
		if (TRUE == oxcical_check_rdate(&apprecurr)) {
			if (FALSE == oxcical_export_rdate(tzid,
				b_allday, pcomponent, &apprecurr)) {
				return FALSE;
			}
		}
	}
	
	propname.kind = MNID_ID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_MEETING, &propname.guid);
	/* PidLidGlobalObjectId */
	lid = 0x00000003;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = PROP_TAG(PT_BINARY, propids.ppropid[0]);
	pvalue = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
	if (NULL != pvalue) {
		ext_buffer_pull_init(&ext_pull, ((BINARY*)pvalue)->pb,
							((BINARY*)pvalue)->cb, alloc, 0);
		if (EXT_ERR_SUCCESS != ext_buffer_pull_globalobjectid(
			&ext_pull, &globalobjectid)) {
			return FALSE;
		}
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
			ext_buffer_push_init(&ext_push, tmp_buff, sizeof(tmp_buff), 0);
			if (EXT_ERR_SUCCESS != ext_buffer_push_globalobjectid(
				&ext_push, &globalobjectid)) {
				return FALSE;
			}
			if (FALSE == encode_hex_binary(tmp_buff,
				ext_push.offset, tmp_buff1, sizeof(tmp_buff1))) {
				return FALSE;
			}
			HX_strupper(tmp_buff1);
			piline = ical_new_simple_line("UID", tmp_buff1);
		}
		if (NULL == piline) {
			return FALSE;
		}
		if (pcomponent->append_line(piline) < 0)
			return false;
	} else {
		time(&cur_time);
		memset(&globalobjectid, 0, sizeof(GLOBALOBJECTID));
		memcpy(globalobjectid.arrayid, EncodedGlobalId, 16);
		globalobjectid.creationtime = rop_util_unix_to_nttime(cur_time);
		globalobjectid.data.cb = 16;
		globalobjectid.data.pc = tmp_buff1;
		guid = guid_random_new();
		ext_buffer_push_init(&ext_push, tmp_buff1, 16, 0);
		ext_buffer_push_guid(&ext_push, &guid);
		ext_buffer_push_init(&ext_push, tmp_buff, sizeof(tmp_buff), 0);
		if (EXT_ERR_SUCCESS != ext_buffer_push_globalobjectid(
			&ext_push, &globalobjectid)) {
			return FALSE;
		}
		if (FALSE == encode_hex_binary(tmp_buff,
			ext_push.offset, tmp_buff1, sizeof(tmp_buff1))) {
			return FALSE;
		}
		HX_strupper(tmp_buff1);
		piline = ical_new_simple_line("UID", tmp_buff1);
		if (NULL == piline) {
			return FALSE;
		}
		if (pcomponent->append_line(piline) < 0)
			return false;
	}
	
	propname.kind = MNID_ID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	/* PidLidExceptionReplaceTime */
	lid = 0x00008228;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag_xrt = PROP_TAG(PT_SYSTIME, propids.ppropid[0]);
	pvalue = tpropval_array_get_propval(
			&pmsg->proplist, proptag_xrt);
	if (NULL == pvalue) {
		propname.kind = MNID_ID;
		propname.plid = &lid;
		rop_util_get_common_pset(PSETID_MEETING, &propname.guid);
		/* PidLidIsException */
		lid = 0x0000000A;
		if (FALSE == get_propids(&propnames, &propids)) {
			return FALSE;
		}
		proptag = PROP_TAG(PT_BOOLEAN, propids.ppropid[0]);
		pvalue = tpropval_array_get_propval(
					&pmsg->proplist, proptag);
		if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
			propname.kind = MNID_ID;
			propname.plid = &lid;
			rop_util_get_common_pset(PSETID_MEETING, &propname.guid);
			/* PidLidStartRecurrenceTime */
			lid = 0x0000000E;
			if (FALSE == get_propids(&propnames, &propids)) {
				return FALSE;
			}
			proptag = PROP_TAG(PT_LONG, propids.ppropid[0]);
			pvalue = tpropval_array_get_propval(
						&pmsg->proplist, proptag);
			if (NULL != pvalue) {
				itime.hour = ((*(uint32_t*)pvalue) & 0x1F000) >> 12;
				itime.minute = ((*(uint32_t*)pvalue) & 0xFC0) >> 6;
				itime.second = (*(uint32_t*)pvalue) & 0x3F;
				/* PidLidGlobalObjectId */
				lid = 0x00000003;
				if (FALSE == get_propids(&propnames, &propids)) {
					return FALSE;
				}
				proptag = PROP_TAG(PT_BINARY, propids.ppropid[0]);
				pvalue = tpropval_array_get_propval(
							&pmsg->proplist, proptag);
				if (NULL != pvalue) {
					ext_buffer_pull_init(&ext_pull, ((BINARY*)pvalue)->pb,
										((BINARY*)pvalue)->cb, alloc, 0);
					if (EXT_ERR_SUCCESS != ext_buffer_pull_globalobjectid(
						&ext_pull, &globalobjectid)) {
						return FALSE;
					} else {
						itime.year = globalobjectid.year;
						itime.month = globalobjectid.month;
						itime.day = globalobjectid.day;
					}
				}
			} else {
				pvalue = NULL;
			}
		} else {
			pvalue = NULL;
		}
	} else {
		if (FALSE == ical_utc_to_datetime(ptz_component,
			rop_util_nttime_to_unix(*(uint64_t*)pvalue), &itime)) {
			return FALSE;
		}
	}
	if (NULL != pvalue) {
		if (FALSE == b_allday) {
			if (NULL == ptz_component) {
				sprintf(tmp_buff, "%04d%02d%02dT%02d%02d%02dZ",
						itime.year, itime.month, itime.day,
						itime.hour, itime.minute, itime.second);
			} else {
				sprintf(tmp_buff, "%04d%02d%02dT%02d%02d%02d",
					itime.year, itime.month, itime.day,
					itime.hour, itime.minute, itime.second);
			}
			piline = ical_new_simple_line("RECURRENCE-ID", tmp_buff);
			if (NULL == piline) {
				return FALSE;
			}
			if (pcomponent->append_line(piline) < 0)
				return false;
			if (NULL != ptz_component) {
				piparam = ical_new_param("TZID");
				if (NULL == piparam) {
					return FALSE;
				}
				if (piline->append_param(piparam) < 0)
					return false;
				if (!piparam->append_paramval(tzid))
					return FALSE;
			}
		} else {
			sprintf(tmp_buff, "%04d%02d%02d",
				itime.year, itime.month, itime.day);
			piline = ical_new_simple_line("RECURRENCE-ID", tmp_buff);
			if (NULL == piline) {
				return FALSE;
			}
			if (pcomponent->append_line(piline) < 0)
				return false;
		}
	} else {
		if (TRUE == b_exceptional) {
			return FALSE;
		}
	}
	
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_SUBJECT);
	if (NULL != pvalue) {
		piline = ical_new_simple_line("SUMMARY", static_cast<char *>(pvalue));
		if (NULL == piline) {
			return FALSE;
		}
		if (pcomponent->append_line(piline) < 0)
			return false;
		if (NULL != planguage) {
			piparam = ical_new_param("LANGUAGE");
			if (NULL == piparam) {
				return FALSE;
			}
			if (piline->append_param(piparam) < 0)
				return false;
			if (!piparam->append_paramval(planguage))
				return FALSE;
		}
	}
	
	if (FALSE == ical_utc_to_datetime(
		ptz_component, start_time, &itime)) {
		return FALSE;
	}
	if (NULL == ptz_component) {
		if (TRUE == b_allday) {
			sprintf(tmp_buff, "%04d%02d%02d",
				itime.year, itime.month, itime.day);
		} else {
			sprintf(tmp_buff, "%04d%02d%02dT%02d%02d%02dZ",
					itime.year, itime.month, itime.day,
					itime.hour, itime.minute, itime.second);
		}
	} else {
		sprintf(tmp_buff, "%04d%02d%02dT%02d%02d%02d",
			itime.year, itime.month, itime.day,
			itime.hour, itime.minute, itime.second);
	}
	piline = ical_new_simple_line("DTSTART", tmp_buff);
	if (NULL == piline) {
		return FALSE;
	}
	if (pcomponent->append_line(piline) < 0)
		return false;
	if (NULL == ptz_component && TRUE == b_allday) {
		piparam = ical_new_param("VALUE");
		if (NULL == piparam) {
			return FALSE;
		}
		if (piline->append_param(piparam) < 0)
			return false;
		if (!piparam->append_paramval("DATE"))
			return FALSE;
	}
	if (NULL != ptz_component) {
		piparam = ical_new_param("TZID");
		if (NULL == piparam) {
			return FALSE;
		}
		if (piline->append_param(piparam) < 0)
			return false;
		if (!piparam->append_paramval(tzid))
			return FALSE;
	}
	
	if (start_time != end_time) {
		if (FALSE == ical_utc_to_datetime(
			ptz_component, end_time, &itime)) {
			return FALSE;
		}
		if (NULL == ptz_component) {
			if (TRUE == b_allday) {
			sprintf(tmp_buff, "%04d%02d%02d",
				itime.year, itime.month, itime.day);
			} else {
				sprintf(tmp_buff, "%04d%02d%02dT%02d%02d%02dZ",
						itime.year, itime.month, itime.day,
						itime.hour, itime.minute, itime.second);
			}
		} else {
			sprintf(tmp_buff, "%04d%02d%02dT%02d%02d%02d",
				itime.year, itime.month, itime.day,
				itime.hour, itime.minute, itime.second);
		}
		piline = ical_new_simple_line("DTEND", tmp_buff);
		if (NULL == piline) {
			return FALSE;
		}
		if (pcomponent->append_line(piline) < 0)
			return false;
		if (NULL == ptz_component && TRUE == b_allday) {
			piparam = ical_new_param("VALUE");
			if (NULL == piparam) {
				return FALSE;
			}
			if (piline->append_param(piparam) < 0)
				return false;
			if (!piparam->append_paramval("DATE"))
				return FALSE;
		}
		if (NULL != ptz_component) {
			piparam = ical_new_param("TZID");
			if (NULL == piparam) {
				return FALSE;
			}
			if (piline->append_param(piparam) < 0)
				return false;
			if (!piparam->append_paramval(tzid))
				return FALSE;
		}
	}
	
	/* PidNameKeywords */
	propname.kind = MNID_STRING;
	propname.pname = deconst("Keywords");
	rop_util_get_common_pset(PS_PUBLIC_STRINGS, &propname.guid);
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = PROP_TAG(PT_MV_UNICODE, propids.ppropid[0]);
	pvalue = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
	if (NULL != pvalue) {
		piline = ical_new_line("CATEGORIES");
		if (NULL == piline) {
			return FALSE;
		}
		if (pical->append_line(piline) < 0)
			return false;
		pivalue = ical_new_value(NULL);
		if (NULL == pivalue) {
			return FALSE;
		}
		if (piline->append_value(pivalue) < 0)
			return false;
		for (i=0; i<((STRING_ARRAY*)pvalue)->count; i++) {
			if (!pivalue->append_subval(static_cast<STRING_ARRAY *>(pvalue)->ppstr[i]))
				return FALSE;
		}
	}
	
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_SENSITIVITY);
	if (NULL == pvalue) {
		piline = ical_new_simple_line("CLASS", "PUBLIC");
	} else {
		switch (*(uint32_t*)pvalue) {
		case 1:
			piline = ical_new_simple_line("CLASS", "PERSONAL");
			break;
		case 2:
			piline = ical_new_simple_line("CLASS", "PRIVATE");
			break;
		case 3:
			piline = ical_new_simple_line("CLASS", "CONFIDENTIAL");
			break;
		default:
			piline = ical_new_simple_line("CLASS", "PUBLIC");
			break;
		}
	}
	if (NULL == piline) {
		return FALSE;
	}
	if (pcomponent->append_line(piline) < 0)
		return false;
	
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_IMPORTANCE);
	if (NULL != pvalue) {
		switch (*(uint32_t*)pvalue) {
		case 1:
			piline = ical_new_simple_line("PRIORITY", "5");
			break;
		case 2:
			piline = ical_new_simple_line("PRIORITY", "1");
			break;
		default:
			piline = ical_new_simple_line("PRIORITY", "9");
			break;
		}
		if (NULL == piline) {
			return FALSE;
		}
		if (pcomponent->append_line(piline) < 0)
			return false;
	}
	
	propname.kind = MNID_ID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_MEETING, &propname.guid);
	if (0 == strcmp(method, "REPLY") ||
		0 == strcmp(method, "COUNTER")) {
		/* PidLidAttendeeCriticalChange */
		lid = 0x00000001;
	} else {
		/* PidLidOwnerCriticalChange */
		lid = 0x0000001A;
	}
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = PROP_TAG(PT_SYSTIME, propids.ppropid[0]);
	pvalue = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
	if (NULL != pvalue) {
		ical_utc_to_datetime(NULL,
			rop_util_nttime_to_unix(
			*(uint64_t*)pvalue), &itime);
		sprintf(tmp_buff, "%04d%02d%02dT%02d%02d%02dZ",
					itime.year, itime.month, itime.day,
					itime.hour, itime.minute, itime.second);
		piline = ical_new_simple_line("DTSTAMP", tmp_buff);
		if (NULL == piline) {
			return FALSE;
		}
		if (pcomponent->append_line(piline) < 0)
			return false;
	}
	
	propname.kind = MNID_ID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	/* PidLidBusyStatus */
	lid = 0x00008205;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = PROP_TAG(PT_LONG, propids.ppropid[0]);
	auto pbusystatus = static_cast<uint32_t *>(tpropval_array_get_propval(
	                   &pmsg->proplist, proptag));
	if (NULL != pbusystatus) {
		switch (*pbusystatus) {
		case 0:
		case 4:
			piline = ical_new_simple_line("TRANSP", "TRANSPARENT");
			if (NULL == piline) {
				return FALSE;
			}
			if (pcomponent->append_line(piline) < 0)
				return false;
			break;
		case 1:
		case 2:
		case 3:
			piline = ical_new_simple_line("TRANSP", "OPAQUE");
			if (NULL == piline) {
				return FALSE;
			}
			if (pcomponent->append_line(piline) < 0)
				return false;
			break;
		}
	}
	
	propname.kind = MNID_ID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	/* PidLidAppointmentSequence */
	lid = 0x00008201;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = PROP_TAG(PT_LONG, propids.ppropid[0]);
	auto psequence = static_cast<uint32_t *>(tpropval_array_get_propval(
	                 &pmsg->proplist, proptag));
	if (NULL != psequence) {
		sprintf(tmp_buff, "%u", *psequence);
		piline = ical_new_simple_line("SEQUENCE", tmp_buff);
		if (NULL == piline) {
			return FALSE;
		}
		if (pcomponent->append_line(piline) < 0)
			return false;
	}
	
	propname.kind = MNID_ID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	/* PidLidLocation */
	lid = 0x00008208;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = PROP_TAG(PT_UNICODE, propids.ppropid[0]);
	pvalue = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
	if (NULL != pvalue) {
		piline = ical_new_simple_line("LOCATION", static_cast<char *>(pvalue));
		if (NULL == piline) {
			return FALSE;
		}
		if (pcomponent->append_line(piline) < 0)
			return false;
		rop_util_get_common_pset(PS_PUBLIC_STRINGS, &propname.guid);
		/* PidNameLocationUrl */
		propname.kind = MNID_STRING;
		propname.pname = deconst("urn:schemas:calendar:locationurl");
		if (FALSE == get_propids(&propnames, &propids)) {
			return FALSE;
		}
		proptag = PROP_TAG(PT_UNICODE, propids.ppropid[0]);
		pvalue = tpropval_array_get_propval(
					&pmsg->proplist, proptag);
		if (NULL != pvalue) {
			piparam = ical_new_param("ALTREP");
			if (NULL == piparam) {
				return FALSE;
			}
			if (piline->append_param(piparam) < 0)
				return false;
			if (!piparam->append_paramval(static_cast<char *>(pvalue)))
				return FALSE;
		}
		if (NULL != planguage) {
			piparam = ical_new_param("LANGUAGE");
			if (NULL == piparam) {
				return FALSE;
			}
			if (piline->append_param(piparam) < 0)
				return false;
			if (!piparam->append_paramval(planguage))
				return FALSE;
		}
	}
	
	if (NULL != psequence) {
		sprintf(tmp_buff, "%u", *psequence);
		piline = ical_new_simple_line(
			"X-MICROSOFT-CDO-APPT-SEQUENCE", tmp_buff);
		if (NULL == piline) {
			return FALSE;
		}
		if (pcomponent->append_line(piline) < 0)
			return false;
	}
	
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_OWNERAPPOINTMENTID);
	if (NULL != pvalue) {
		sprintf(tmp_buff, "%u", *(uint32_t*)pvalue);
		piline = ical_new_simple_line(
			"X-MICROSOFT-CDO-OWNERAPPTID", tmp_buff);
		if (NULL == piline) {
			return FALSE;
		}
		if (pcomponent->append_line(piline) < 0)
			return false;
	}
	
	if (NULL != pbusystatus) {
		switch (*pbusystatus) {
		case 0:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-BUSYSTATUS", "FREE");
			if (NULL == piline) {
				return FALSE;
			}
			if (pcomponent->append_line(piline) < 0)
				return false;
			break;
		case 1:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-BUSYSTATUS", "TENTATIVE");
			if (NULL == piline) {
				return FALSE;
			}
			if (pcomponent->append_line(piline) < 0)
				return false;
			break;
		case 2:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-BUSYSTATUS", "BUSY");
			if (NULL == piline) {
				return FALSE;
			}
			if (pcomponent->append_line(piline) < 0)
				return false;
			break;
		case 3:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-BUSYSTATUS", "OOF");
			if (NULL == piline) {
				return FALSE;
			}
			if (pcomponent->append_line(piline) < 0)
				return false;
			break;
		}
	}
	
	propname.kind = MNID_ID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	/* PidLidIntendedBusyStatus */
	lid = 0x00008224;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = PROP_TAG(PT_LONG, propids.ppropid[0]);
	pvalue = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
	if (NULL != pvalue) {
		switch (*(uint32_t*)pvalue) {
		case 0:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-INTENDEDSTATUS", "FREE");
			if (NULL == piline) {
				return FALSE;
			}
			if (pcomponent->append_line(piline) < 0)
				return false;
			break;
		case 1:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-INTENDEDSTATUS", "TENTATIVE");
			if (NULL == piline) {
				return FALSE;
			}
			if (pcomponent->append_line(piline) < 0)
				return false;
			break;
		case 2:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-INTENDEDSTATUS", "BUSY");
			if (NULL == piline) {
				return FALSE;
			}
			if (pcomponent->append_line(piline) < 0)
				return false;
			break;
		case 3:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-INTENDEDSTATUS", "OOF");
			if (NULL == piline) {
				return FALSE;
			}
			if (pcomponent->append_line(piline) < 0)
				return false;
			break;
		}
	}
	
	if (TRUE == b_allday) {
		piline = ical_new_simple_line(
			"X-MICROSOFT-CDO-ALLDAYEVENT", "TRUE");
	} else {
		piline = ical_new_simple_line(
			"X-MICROSOFT-CDO-ALLDAYEVENT", "FALSE");
	}
	if (NULL == piline) {
		return FALSE;
	}
	if (pcomponent->append_line(piline) < 0)
		return false;
	
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_IMPORTANCE);
	if (NULL != pvalue) {
		switch (*(uint32_t*)pvalue) {
		case 0:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-IMPORTANCE", "0");
			if (NULL == piline) {
				return FALSE;
			}
			if (pcomponent->append_line(piline) < 0)
				return false;
			break;
		case 1:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-IMPORTANCE", "1");
			if (NULL == piline) {
				return FALSE;
			}
			if (pcomponent->append_line(piline) < 0)
				return false;
			break;
		case 2:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-IMPORTANCE", "2");
			if (NULL == piline) {
				return FALSE;
			}
			if (pcomponent->append_line(piline) < 0)
				return false;
			break;
		}
	}
	
	if (TRUE == b_exceptional) {
		piline = ical_new_simple_line("X-MICROSOFT-CDO-INSTTYPE", "3");
	} else {
		if (TRUE == b_recurrence) {
			piline = ical_new_simple_line("X-MICROSOFT-CDO-INSTTYPE", "1");
		} else {
			piline = ical_new_simple_line("X-MICROSOFT-CDO-INSTTYPE", "0");
		}
	}
	if (NULL == piline) {
		return FALSE;
	}
	if (pcomponent->append_line(piline) < 0)
		return false;
	
	propname.kind = MNID_ID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	/* PidLidAppointmentNotAllowPropose */
	lid = 0x0000825A;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = PROP_TAG(PT_BOOLEAN, propids.ppropid[0]);
	pvalue = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
	if (NULL != pvalue) {
		if (0 == *(uint8_t*)pvalue) {
			piline = ical_new_simple_line(
				"X-MICROSOFT-DISALLOW-COUNTER", "FALSE");
		} else {
			piline = ical_new_simple_line(
				"X-MICROSOFT-DISALLOW-COUNTER", "TRUE");
		}
		if (NULL == piline) {
			return FALSE;
		}
		if (pcomponent->append_line(piline) < 0)
			return false;
	}
	
	if (FALSE == b_exceptional && NULL != pmsg->children.pattachments) {
		for (i=0; i<pmsg->children.pattachments->count; i++) {
			if (NULL == pmsg->children.pattachments->pplist[i]->pembedded) {
				continue;
			}
			pembedded = pmsg->children.pattachments->pplist[i]->pembedded;
			pvalue = tpropval_array_get_propval(
							&pembedded->proplist,
							PROP_TAG_MESSAGECLASS);
			if (NULL == pvalue) {
				pvalue = tpropval_array_get_propval(
							&pembedded->proplist,
							PROP_TAG_MESSAGECLASS_STRING8);
			}
			if (pvalue == nullptr || strcasecmp(static_cast<char *>(pvalue),
			    "IPM.OLE.CLASS.{00061055-0000-0000-C000-000000000046}"))
				continue;
			if (NULL == tpropval_array_get_propval(
				&pembedded->proplist, proptag_xrt)) {
				continue;
			}
			if (FALSE == oxcical_export_internal(method, tzid,
				ptz_component, pembedded, pical, entryid_to_username,
				essdn_to_username, lcid_to_ltag, alloc, get_propids)) {
				return FALSE;
			}
		}
	}
	
	propname.kind = MNID_ID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	/* PidLidReminderSet */
	lid = 0x00008503;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = PROP_TAG(PT_BOOLEAN, propids.ppropid[0]);
	pvalue = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		pcomponent = ical_new_component("VALARM");
		if (NULL == pcomponent) {
			return FALSE;
		}
		pical->append_comp(pcomponent);
		piline = ical_new_simple_line("DESCRIPTION", "REMINDER");
		if (NULL == piline) {
			return FALSE;
		}
		if (pcomponent->append_line(piline) < 0)
			return false;
		propname.kind = MNID_ID;
		propname.plid = &lid;
		rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
		/* PidLidReminderDelta */
		lid = 0x00008501;
		if (FALSE == get_propids(&propnames, &propids)) {
			return FALSE;
		}
		proptag = PROP_TAG(PT_LONG, propids.ppropid[0]);
		pvalue = tpropval_array_get_propval(
					&pmsg->proplist, proptag);
		if (NULL == pvalue || 0x5AE980E1 == *(uint32_t*)pvalue) {
			strcpy(tmp_buff, "-PT15M");
		} else {
			sprintf(tmp_buff, "-PT%uM", *(uint32_t*)pvalue);
		}
		piline = ical_new_simple_line("TRIGGER", tmp_buff);
		if (NULL == piline) {
			return FALSE;
		}
		if (pcomponent->append_line(piline) < 0)
			return false;
		piparam = ical_new_param("RELATED");
		if (NULL == piparam) {
			return FALSE;
		}
		if (piline->append_param(piparam) < 0)
			return false;
		if (!piparam->append_paramval("START"))
			return FALSE;
		piline = ical_new_simple_line("ACTION", "DISPLAY");
		if (NULL == piline) {
			return FALSE;
		}
		if (pcomponent->append_line(piline) < 0)
			return false;
	}
	return TRUE;
}

BOOL oxcical_export(const MESSAGE_CONTENT *pmsg, ICAL *pical,
	EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
	ENTRYID_TO_USERNAME entryid_to_username,
	ESSDN_TO_USERNAME essdn_to_username,
	LCID_TO_LTAG lcid_to_ltag)
{
	return oxcical_export_internal(NULL, NULL,
			NULL, (MESSAGE_CONTENT*)pmsg, pical,
			entryid_to_username, essdn_to_username,
			lcid_to_ltag, alloc, get_propids);
}

