#include "tpropval_array.h"
#include "tarray_set.h"
#include "ext_buffer.h"
#include "mail_func.h"
#include "int_hash.h"
#include "rop_util.h"
#include "oxcical.h"
#include "util.h"
#include "guid.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>


#define MAX_TZRULE_NUMBER						128

#define MAX_TZDEFINITION_LENGTH					(68*MAX_TZRULE_NUMBER+270)

typedef struct _UID_EVENTS {
	DOUBLE_LIST_NODE node;
	const char *puid;
	DOUBLE_LIST list;
} UID_EVENTS;

static BOOL oxcical_parse_vtsubcomponent(
	ICAL_COMPONENT *psub_component,
	int32_t *pbias, int16_t *pyear,
	SYSTEMTIME *pdate)
{
	int hour;
	int minute;
	BOOL b_utc;
	int dayofweek;
	int weekorder;
	ICAL_TIME itime;
	ICAL_LINE *piline;
	const char *pvalue;
	const char *pvalue1;
	const char *pvalue2;
	
	memset(pdate, 0, sizeof(SYSTEMTIME));
	piline = ical_get_line(psub_component, "TZOFFSETTO");
	if (NULL == piline) {
		return FALSE;
	}
	pvalue = ical_get_first_subvalue(piline);
	if (NULL == pvalue) {
		return FALSE;
	}
	if (FALSE == ical_parse_utc_offset(pvalue, &hour, &minute)) {
		return FALSE;
	}
	*pbias = 60*hour + minute;
	piline = ical_get_line(psub_component, "DTSTART");
	if (NULL == piline) {
		return FALSE;
	}
	if (NULL != ical_get_first_paramval(piline, "TZID")) {
		return FALSE;
	}
	pvalue = ical_get_first_subvalue(piline);
	if (NULL == pvalue) {
		return FALSE;
	}
	if (FALSE == ical_parse_datetime(pvalue,
		&b_utc, &itime) || TRUE == b_utc) {
		return FALSE;
	}
	*pyear = itime.year;
	pdate->hour = itime.hour;
	pdate->minute = itime.minute;
	pdate->second = itime.second;
	piline = ical_get_line(psub_component, "RRULE");
	if (NULL != piline) {
		pvalue = ical_get_first_subvalue_by_name(piline, "FREQ");
		if (NULL == pvalue || 0 != strcasecmp(pvalue, "YEARLY")) {
			return FALSE;
		}
		pvalue = ical_get_first_subvalue_by_name(piline, "BYDAY");
		pvalue1 = ical_get_first_subvalue_by_name(piline, "BYMONTHDAY");
		if ((NULL == pvalue && NULL == pvalue1) ||
			(NULL != pvalue && NULL != pvalue1)) {
			return FALSE;
		}
		pvalue2 = ical_get_first_subvalue_by_name(piline, "BYMONTH");
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
			if (FALSE == ical_parse_byday(pvalue,
				&dayofweek, &weekorder)) {
				return FALSE;
			}
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
	return ((TZRULE*)prule1)->year - ((TZRULE*)prule2)->year;
}

static BOOL oxcical_parse_tzdefinition(
	ICAL_COMPONENT *pvt_component,
	TIMEZONEDEFINITION *ptz_definition)
{
	int i;
	BOOL b_found;
	int32_t bias;
	int16_t year;
	SYSTEMTIME date;
	BOOL b_daylight;
	ICAL_LINE *piline;
	TZRULE *pstandard_rule;
	TZRULE *pdaylight_rule;
	DOUBLE_LIST_NODE *pnode;
	ICAL_COMPONENT *pcomponent;
	
	ptz_definition->major = 2;
	ptz_definition->minor = 1;
	ptz_definition->reserved = 0x0002;
	piline = ical_get_line(pvt_component, "TZID");
	if (NULL == piline) {
		return FALSE;
	}
	ptz_definition->keyname = (char*)ical_get_first_subvalue(piline);
	if (NULL == ptz_definition->keyname) {
		return FALSE;
	}
	ptz_definition->crules = 0;
	for (pnode=double_list_get_head(&pvt_component->component_list);
		NULL!=pnode; pnode=double_list_get_after(
		&pvt_component->component_list, pnode)) {
		pcomponent = (ICAL_COMPONENT*)pnode->pdata;
		if (0 == strcasecmp(pcomponent->name, "STANDARD")) {
			b_daylight = FALSE;
		} else if (0 == strcasecmp(pcomponent->name, "DAYLIGHT")) {
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
static BOOL oxcical_parse_rrule(ICAL_COMPONENT *ptz_component,
	ICAL_LINE *piline, uint16_t calendartype, time_t start_time,
	uint32_t duration_minutes, APPOINTMENTRECURRENCEPATTERN *papprecurr)
{
	int tmp_int;
	time_t tmp_time;
	ICAL_TIME itime;
	ICAL_TIME itime1;
	ICAL_RRULE irrule;
	BOOL b_exceptional;
	const char *pvalue;
	uint32_t patterntype;
	ICAL_TIME itime_base;
	ICAL_TIME itime_first;
	const ICAL_TIME *pitime;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST *psubval_list;
	
	if (NULL != ical_get_subval_list(piline, "BYYEARDAY") ||
		NULL != ical_get_subval_list(piline, "BYWEEKNO")) {
		return FALSE;
	}
	psubval_list = ical_get_subval_list(piline, "BYMONTHDAY");
	if (NULL != psubval_list && double_list_get_nodes_num(
		psubval_list) > 1) {
		return FALSE;
	}
	psubval_list = ical_get_subval_list(piline, "BYSETPOS");
	if (NULL != psubval_list && double_list_get_nodes_num(
		psubval_list) > 1) {
		return FALSE;
	}
	psubval_list = ical_get_subval_list(piline, "BYSECOND");
	if (NULL != psubval_list) {
		if (double_list_get_nodes_num(psubval_list) > 1) {
			return FALSE;
		}
		pvalue = ical_get_first_subvalue_by_name(piline, "BYSECOND");
		if (NULL != pvalue && atoi(pvalue) != start_time%60) {
			return FALSE;
		}
	}
	if (FALSE == ical_parse_rrule(ptz_component,
		start_time, &piline->value_list, &irrule)) {
		return FALSE;
	}
	b_exceptional = ical_rrule_exceptional(&irrule);
	if (TRUE == b_exceptional) {
		if (FALSE == ical_rrule_iterate(&irrule)) {
			return FALSE;
		}
	}
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
	if (TRUE == ical_rrule_endless(&irrule)) {
SET_INFINITIVE:
		papprecurr->recurrencepattern.endtype = ENDTYPE_NEVER_END;
		papprecurr->recurrencepattern.occurrencecount = 0x0000000A;
		papprecurr->recurrencepattern.enddate = ENDDATE_MISSING;
	} else {
		itime = ical_rrule_instance_itime(&irrule);
		while (TRUE == ical_rrule_iterate(&irrule)) {
			itime1 = ical_rrule_instance_itime(&irrule);
			if (itime1.year > 4500) {
				goto SET_INFINITIVE;
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
		if (TRUE == b_exceptional) {
			papprecurr->recurrencepattern.occurrencecount --;
		}
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
		if (NULL != ical_get_subval_list(piline, "BYDAY") ||
			NULL != ical_get_subval_list(piline, "BYMONTH") ||
			NULL != ical_get_subval_list(piline, "BYSETPOS")) {
			return FALSE;
		}
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
		if (NULL != ical_get_subval_list(piline, "BYMONTH") ||
			NULL != ical_get_subval_list(piline, "BYSETPOS")) {
			return FALSE;
		}
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
		if (TRUE == ical_rrule_check_bymask(&irrule, RRULE_BY_DAY)) {
			psubval_list = ical_get_subval_list(piline, "BYDAY");
			papprecurr->recurrencepattern.
				patterntypespecific.weekrecurrence = 0;
			for (pnode=double_list_get_head(psubval_list); NULL!=pnode;
				pnode=double_list_get_after(psubval_list, pnode)) {
				if (0 == strcasecmp(pnode->pdata, "SU")) {
					papprecurr->recurrencepattern.
						patterntypespecific.weekrecurrence |= 0x00000001;
				} else if (0 == strcasecmp(pnode->pdata, "MO")) {
					papprecurr->recurrencepattern.
						patterntypespecific.weekrecurrence |= 0x00000002;
				} else if (0 == strcasecmp(pnode->pdata, "TU")) {
					papprecurr->recurrencepattern.
						patterntypespecific.weekrecurrence |= 0x00000004;
				} else if (0 == strcasecmp(pnode->pdata, "WE")) {
					papprecurr->recurrencepattern.
						patterntypespecific.weekrecurrence |= 0x00000008;
				} else if (0 == strcasecmp(pnode->pdata, "TH")) {
					papprecurr->recurrencepattern.
						patterntypespecific.weekrecurrence |= 0x00000010;
				} else if (0 == strcasecmp(pnode->pdata, "FR")) {
					papprecurr->recurrencepattern.
						patterntypespecific.weekrecurrence |= 0x00000020;
				} else if (0 == strcasecmp(pnode->pdata, "SA")) {
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
		if (NULL != ical_get_subval_list(piline, "BYMONTH")) {
			return FALSE;
		}
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
		if (TRUE == ical_rrule_check_bymask(&irrule, RRULE_BY_DAY) &&
			TRUE == ical_rrule_check_bymask(&irrule, RRULE_BY_SETPOS)) {
			patterntype = PATTERNTYPE_MONTHNTH;
			psubval_list = ical_get_subval_list(piline, "BYDAY");
			papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence = 0;
			for (pnode=double_list_get_head(psubval_list); NULL!=pnode;
				pnode=double_list_get_after(psubval_list, pnode)) {
				if (0 == strcasecmp(pnode->pdata, "SU")) {
					papprecurr->recurrencepattern.
								patterntypespecific.monthnth.
								weekrecurrence |= 0x00000001;
				} else if (0 == strcasecmp(pnode->pdata, "MO")) {
					papprecurr->recurrencepattern.
								patterntypespecific.monthnth.
								weekrecurrence |= 0x00000002;
				} else if (0 == strcasecmp(pnode->pdata, "TU")) {
					papprecurr->recurrencepattern.
								patterntypespecific.monthnth.
								weekrecurrence |= 0x00000004;
				} else if (0 == strcasecmp(pnode->pdata, "WE")) {
					papprecurr->recurrencepattern.
								patterntypespecific.monthnth.
								weekrecurrence |= 0x00000008;
				} else if (0 == strcasecmp(pnode->pdata, "TH")) {
					papprecurr->recurrencepattern.
								patterntypespecific.monthnth.
								weekrecurrence |= 0x00000010;
				} else if (0 == strcasecmp(pnode->pdata, "FR")) {
					papprecurr->recurrencepattern.
								patterntypespecific.monthnth.
								weekrecurrence |= 0x00000020;
				} else if (0 == strcasecmp(pnode->pdata, "SA")) {
					papprecurr->recurrencepattern.
								patterntypespecific.monthnth.
								weekrecurrence |= 0x00000040;
				}
			}
			pvalue = ical_get_first_subvalue_by_name(piline, "BYSETPOS");
			tmp_int = atoi(pvalue);
			if (tmp_int > 4 || tmp_int < -1) {
				return FALSE;
			} else if (-1 == tmp_int) {
				tmp_int = 5;
			}
			papprecurr->recurrencepattern.patterntypespecific.
							monthnth.recurrencenum = tmp_int;
		} else {
			if (TRUE == ical_rrule_check_bymask(&irrule, RRULE_BY_DAY) ||
				TRUE == ical_rrule_check_bymask(&irrule, RRULE_BY_SETPOS)) {
				return FALSE;
			}
			patterntype = PATTERNTYPE_MONTH;
			pvalue = ical_get_first_subvalue_by_name(piline, "BYMONTHDAY");
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
		if (TRUE == ical_rrule_check_bymask(&irrule, RRULE_BY_DAY) &&
			TRUE == ical_rrule_check_bymask(&irrule, RRULE_BY_SETPOS) &&
			TRUE == ical_rrule_check_bymask(&irrule, RRULE_BY_MONTH)) {
			if (TRUE == ical_rrule_check_bymask(
				&irrule, RRULE_BY_MONTHDAY)) {
				return FALSE;
			}
			patterntype = PATTERNTYPE_MONTHNTH;
			psubval_list = ical_get_subval_list(piline, "BYDAY");
			papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence = 0;
			for (pnode=double_list_get_head(psubval_list); NULL!=pnode;
				pnode=double_list_get_after(psubval_list, pnode)) {
				if (0 == strcasecmp(pnode->pdata, "SU")) {
					papprecurr->recurrencepattern.
						patterntypespecific.monthnth.
						weekrecurrence |= 0x00000001;
				} else if (0 == strcasecmp(pnode->pdata, "MO")) {
					papprecurr->recurrencepattern.
						patterntypespecific.monthnth.
						weekrecurrence |= 0x00000002;
				} else if (0 == strcasecmp(pnode->pdata, "TU")) {
					papprecurr->recurrencepattern.
						patterntypespecific.monthnth.
						weekrecurrence |= 0x00000004;
				} else if (0 == strcasecmp(pnode->pdata, "WE")) {
					papprecurr->recurrencepattern.
						patterntypespecific.monthnth.
						weekrecurrence |= 0x00000008;
				} else if (0 == strcasecmp(pnode->pdata, "TH")) {
					papprecurr->recurrencepattern.
						patterntypespecific.monthnth.
						weekrecurrence |= 0x00000010;
				} else if (0 == strcasecmp(pnode->pdata, "FR")) {
					papprecurr->recurrencepattern.
						patterntypespecific.monthnth.
						weekrecurrence |= 0x00000020;
				} else if (0 == strcasecmp(pnode->pdata, "SA")) {
					papprecurr->recurrencepattern.
						patterntypespecific.monthnth.
						weekrecurrence |= 0x00000040;
				}
			}
			pvalue = ical_get_first_subvalue_by_name(piline, "BYSETPOS");
			tmp_int = atoi(pvalue);
			if (tmp_int > 4 || tmp_int < -1) {
				return FALSE;
			} else if (-1 == tmp_int) {
				tmp_int = 5;
			}
			papprecurr->recurrencepattern.patterntypespecific.
							monthnth.recurrencenum = tmp_int;
		} else {
			if (TRUE == ical_rrule_check_bymask(&irrule, RRULE_BY_DAY) ||
				TRUE == ical_rrule_check_bymask(&irrule, RRULE_BY_SETPOS)) {
				return FALSE;
			}
			patterntype = PATTERNTYPE_MONTH;
			pvalue = ical_get_first_subvalue_by_name(piline, "BYMONTHDAY");
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

static ICAL_COMPONENT* oxcical_find_vtimezone(ICAL *pical, const char *tzid)
{
	ICAL_LINE *piline;
	const char *pvalue;
	DOUBLE_LIST_NODE *pnode;
	ICAL_COMPONENT *pcomponent;
	
	for (pnode=double_list_get_head(&pical->component_list); NULL!=pnode;
		pnode=double_list_get_after(&pical->component_list, pnode)) {
		pcomponent = (ICAL_COMPONENT*)pnode->pdata;
		if (0 != strcasecmp(pcomponent->name, "VTIMEZONE")) {
			continue;
		}
		piline = ical_get_line(pcomponent, "TZID");
		if (NULL == piline) {
			continue;
		}
		pvalue = ical_get_first_subvalue(piline);
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
	ICAL_COMPONENT *ptz_component, INT_HASH_TABLE *phash,
	uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	static uint32_t lid1;
	static uint32_t lid2;
	TAGGED_PROPVAL propval;
	PROPERTY_NAME propname;
	TIMEZONEDEFINITION tz_definition;
	TZRULE rules_buff[MAX_TZRULE_NUMBER];
	char bin_buff[MAX_TZDEFINITION_LENGTH];
	
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
	if (TRUE == b_dtstart) {
		/* PidLidAppointmentTimeZoneDefinitionStartDisplay */
		lid1 = 0x0000825E;
		propname.plid = &lid1;
	} else {
		/* PidLidAppointmentTimeZoneDefinitionEndDisplay */
		lid2 = 0x0000825F;
		propname.plid = &lid2;
	}
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_BINARY;
	propval.pvalue = &tmp_bin;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_recurring_timezone(
	ICAL_COMPONENT *ptz_component, INT_HASH_TABLE *phash,
	uint16_t *plast_propid, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	ICAL_LINE *piline;
	const char *ptzid;
	static uint32_t lid;
	static uint32_t lid1;
	static uint32_t lid2;
	TAGGED_PROPVAL propval;
	PROPERTY_NAME propname;
	TIMEZONESTRUCT tz_struct;
	TIMEZONEDEFINITION tz_definition;
	TZRULE rules_buff[MAX_TZRULE_NUMBER];
	char bin_buff[MAX_TZDEFINITION_LENGTH];
	
	tz_definition.prules = rules_buff;
	if (FALSE == oxcical_parse_tzdefinition(
		ptz_component, &tz_definition)) {
		return FALSE;
	}
	piline = ical_get_line(ptz_component, "TZID");
	if (NULL == piline) {
		return FALSE;
	}
	ptzid = ical_get_first_subvalue(piline);
	if (NULL == ptzid) {
		return FALSE;
	}
	/* PidLidTimeZoneDescription */
	lid = 0x00008234;
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_WSTRING;
	propval.pvalue = (void*)ptzid;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
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
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid1;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_BINARY;
	propval.pvalue = &tmp_bin;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
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
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid2;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_BINARY;
	propval.pvalue = &tmp_bin;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
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
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_BYTE;
	propval.pvalue = &tmp_byte;
	tmp_byte = 1;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_recipients(ICAL_COMPONENT*pmain_event,
	USERNAME_TO_ENTRYID username_to_entryid, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	int address_type;
	uint8_t tmp_byte;
	const char *prole;
	const char *prsvp;
	ICAL_LINE *piline;
	uint32_t tmp_int32;
	TARRAY_SET *prcpts;
	char tmp_buff[1024];
	const char *pcutype;
	const char *paddress;
	TAGGED_PROPVAL propval;
	DOUBLE_LIST_NODE *pnode;
	TPROPVAL_ARRAY *pproplist;
	const char *pdisplay_name;
	const char *pmessage_class;
	
	pmessage_class = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_MESSAGECLASS);
	if (NULL == pmessage_class) {
		pmessage_class = tpropval_array_get_propval(
			&pmsg->proplist, PROP_TAG_MESSAGECLASS_STRING8);
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
	for (pnode=double_list_get_head(&pmain_event->line_list); NULL!=pnode;
		pnode=double_list_get_after(&pmain_event->line_list, pnode)) {
		piline = (ICAL_LINE*)pnode->pdata;
		if (0 != strcasecmp(piline->name, "ATTENDEE")) {
			continue;
		}
		paddress = ical_get_first_subvalue(piline);
		if (NULL == paddress || 0 != strncasecmp(paddress, "MAILTO:", 7)) {
			continue;
		}
		paddress += 7;
		pdisplay_name = ical_get_first_paramval(piline, "CN");
		pcutype = ical_get_first_paramval(piline, "CUTYPE");
		prole = ical_get_first_paramval(piline, "ROLE");
		prsvp = ical_get_first_paramval(piline, "RSVP");
		if (NULL != prsvp && 0 == strcasecmp(prsvp, "TRUE")) {
			tmp_byte = 1;
		}
		pproplist = tpropval_array_init();
		if (NULL == pproplist) {
			return FALSE;
		}
		if (FALSE == tarray_set_append_internal(prcpts, pproplist)) {
			tpropval_array_free(pproplist);
			return FALSE;
		}
		propval.proptag = PROP_TAG_ADDRESSTYPE;
		propval.pvalue = "SMTP";
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_EMAILADDRESS;
		propval.pvalue = (void*)paddress;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_SMTPADDRESS;
		propval.pvalue = (void*)paddress;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		if (NULL == pdisplay_name) {
			pdisplay_name = paddress;
		}
		propval.proptag = PROP_TAG_DISPLAYNAME;
		propval.pvalue = (void*)pdisplay_name;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_TRANSMITTABLEDISPLAYNAME;
		propval.pvalue = (void*)pdisplay_name;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		tmp_bin.pb = tmp_buff;
		tmp_bin.cb = 0;
		if (FALSE == username_to_entryid(paddress,
			pdisplay_name, &tmp_bin, &address_type)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_ENTRYID;
		propval.pvalue = &tmp_bin;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_RECIPIENTENTRYID;
		propval.pvalue = &tmp_bin;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_RECORDKEY;
		propval.pvalue = &tmp_bin;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
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
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_OBJECTTYPE;
		propval.pvalue = &tmp_int32;
		if (ADDRESS_TYPE_MLIST == address_type) {
			tmp_int32 = OBJECT_DLIST;
		} else {
			tmp_int32 = OBJECT_USER;
		}
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
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
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		tmp_byte = 1;
		propval.proptag = PROP_TAG_RESPONSIBILITY;
		propval.pvalue = &tmp_byte;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		tmp_int32 = 1;
		propval.proptag = PROP_TAG_RECIPIENTFLAGS;
		propval.pvalue = &tmp_int32;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
	}
	propval.proptag = PROP_TAG_RESPONSEREQUESTED;
	propval.pvalue = &tmp_byte;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_REPLYREQUESTED;
	propval.pvalue = &tmp_byte;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_parse_categoris(ICAL_LINE *piline,
	INT_HASH_TABLE *phash, uint16_t *plast_propid,
	MESSAGE_CONTENT *pmsg)
{
	char *tmp_buff[128];
	ICAL_VALUE *pivalue;
	TAGGED_PROPVAL propval;
	PROPERTY_NAME propname;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	STRING_ARRAY strings_array;
	
	pnode = double_list_get_head(&piline->value_list);
	if (NULL == pnode) {
		return TRUE;
	}
	pivalue = (ICAL_VALUE*)pnode->pdata;
	strings_array.count = 0;
	strings_array.ppstr = tmp_buff;
	for (pnode1=double_list_get_head(&pivalue->subval_list);
		NULL!=pnode1; pnode1=double_list_get_after(
		&pivalue->subval_list, pnode1)) {
		if (NULL == pnode1->pdata) {
			continue;
		}
		strings_array.ppstr[strings_array.count] = pnode1->pdata;
		strings_array.count ++;
		if (strings_array.count >= 128) {
			break;
		}
	}
	if (0 != strings_array.count && strings_array.count < 128) {
		/* PidNameKeywords */
		propname.kind = KIND_NAME;
		rop_util_get_common_pset(PS_PUBLIC_STRINGS, &propname.guid);
		propname.pname = "Keywords";
		if (1 != int_hash_add(phash, *plast_propid, &propname)) {
			return FALSE;
		}
		propval.proptag = ((uint32_t)(*plast_propid)) << 16;
		propval.proptag |= PROPVAL_TYPE_WSTRING_ARRAY;
		propval.pvalue = &strings_array;
		if (FALSE == tpropval_array_set_propval(
			&pmsg->proplist, &propval)) {
			return FALSE;
		}
		(*plast_propid) ++;
	}
	return TRUE;
}

static BOOL oxcical_parse_class(ICAL_LINE *piline, MESSAGE_CONTENT *pmsg)
{
	uint32_t tmp_int32;
	const char *pvalue;
	TAGGED_PROPVAL propval;
	
	pvalue = ical_get_first_subvalue(piline);
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
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_parse_body(ICAL_LINE *piline, MESSAGE_CONTENT *pmsg)
{
	const char *pvalue;
	TAGGED_PROPVAL propval;
	
	pvalue = ical_get_first_subvalue(piline);
	if (NULL == pvalue) {
		return TRUE;
	}
	propval.proptag = PROP_TAG_BODY;
	propval.pvalue = (void*)pvalue;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_parse_html(ICAL_LINE *piline, MESSAGE_CONTENT *pmsg)
{
	BINARY tmp_bin;
	const char *pvalue;
	uint32_t tmp_int32;
	TAGGED_PROPVAL propval;
	
	pvalue = ical_get_first_subvalue(piline);
	if (NULL == pvalue) {
		return TRUE;
	}
	propval.proptag = PROP_TAG_HTML;
	propval.pvalue = &tmp_bin;
	tmp_bin.cb = strlen(pvalue);
	tmp_bin.pb = (void*)pvalue;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_INTERNETCODEPAGE;
	propval.pvalue = &tmp_int32;
	tmp_int32 = 65001;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_parse_dtstamp(ICAL_LINE *piline,
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
	
	pvalue = ical_get_first_subvalue(piline);
	if (NULL == pvalue) {
		return TRUE;
	}
	if (FALSE == ical_datetime_to_utc(NULL, pvalue, &tmp_time)) {
		return TRUE;
	}
	if (0 == strcasecmp(method, "REPLY") ||
		0 == strcasecmp(method, "COUNTER")) {
		/* PidLidAttendeeCriticalChange */
		lid1 = 0x00000001;
		propname.plid = &lid1;
	} else {
		/* PidLidOwnerCriticalChange */
		lid2 = 0x0000001A;
		propname.plid = &lid2;
	}
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_MEETING, &propname.guid);
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_FILETIME;
	propval.pvalue = &tmp_int64;
	tmp_int64 = rop_util_unix_to_nttime(tmp_time);
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_start_end(BOOL b_start,
	BOOL b_proposal, ICAL_COMPONENT *pmain_event,
	time_t unix_time, INT_HASH_TABLE *phash,
	uint16_t *plast_propid,  MESSAGE_CONTENT *pmsg)
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
		propname.kind = KIND_LID;
		rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
		if (1 != int_hash_add(phash, *plast_propid, &propname)) {
			return FALSE;
		}
		propval.proptag = ((uint32_t)(*plast_propid)) << 16;
		propval.proptag |= PROPVAL_TYPE_FILETIME;
		propval.pvalue = &tmp_int64;
		if (FALSE == tpropval_array_set_propval(
			&pmsg->proplist, &propval)) {
			return FALSE;
		}
		(*plast_propid) ++;
	}
	if (FALSE == b_proposal ||
		(NULL == ical_get_line(pmain_event, "X-MS-OLK-ORIGINALEND") &&
		NULL == ical_get_line(pmain_event, "X-MS-OLK-ORIGINALSTART"))) {
		if (TRUE == b_start) {
			/* PidLidAppointmentStartWhole */
			lid3 = 0x0000820D;
			propname.plid = &lid3;
		} else {
			/* PidLidAppointmentEndWhole */
			lid4 = 0x0000820E;
			propname.plid = &lid4;
		}
		propname.kind = KIND_LID;
		rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
		if (1 != int_hash_add(phash, *plast_propid, &propname)) {
			return FALSE;
		}
		propval.proptag = ((uint32_t)(*plast_propid)) << 16;
		propval.proptag |= PROPVAL_TYPE_FILETIME;
		propval.pvalue = &tmp_int64;
		if (FALSE == tpropval_array_set_propval(
			&pmsg->proplist, &propval)) {
			return FALSE;
		}
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
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_BYTE;
	propval.pvalue = &tmp_byte;
	tmp_byte = 1;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	if (NULL != pexception) {
		pexception->overrideflags |= OVERRIDEFLAG_SUBTYPE;
		pexception->subtype = 1;
	}
	return TRUE;
}

static BOOL oxcical_parse_dates(ICAL_COMPONENT *ptz_component,
	ICAL_LINE *piline, uint32_t *pcount, uint32_t *pdates)
{
	int i;
	BOOL b_utc;
	ICAL_TIME itime;
	time_t tmp_time;
	uint32_t tmp_date;
	const char *pvalue;
	ICAL_VALUE *pivalue;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	
	pnode = double_list_get_head(&piline->value_list);
	if (NULL == pnode) {
		return TRUE;
	}
	*pcount = 0;
	pivalue = (ICAL_VALUE*)pnode->pdata;
	pvalue = ical_get_first_paramval(piline, "VALUE");
	if (NULL == pvalue || 0 == strcasecmp(pvalue, "DATE-TIME")) {
		for (pnode1=double_list_get_head(&pivalue->subval_list);
			NULL!=pnode1; pnode1=double_list_get_after(
			&pivalue->subval_list, pnode1)) {
			if (NULL == pnode1->pdata) {
				continue;
			}
			if (FALSE == ical_parse_datetime(
				pnode1->pdata, &b_utc, &itime)) {
				continue;
			}
			if (TRUE == b_utc && NULL != ptz_component) {
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
		for (pnode1=double_list_get_head(&pivalue->subval_list);
			NULL!=pnode1; pnode1=double_list_get_after(
			&pivalue->subval_list, pnode1)) {
			if (NULL == pnode1->pdata) {
				continue;
			}
			memset(&itime, 0, sizeof(ICAL_TIME));
			if (FALSE == ical_parse_date(pnode1->pdata,
				&itime.year, &itime.month, &itime.day)) {
				continue;
			}
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
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_LONG;
	propval.pvalue = &minutes;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_dtvalue(
	ICAL_COMPONENT *ptz_component,
	ICAL_LINE *piline, BOOL *pb_utc,
	ICAL_TIME *pitime, time_t *putc_time)
{
	const char *pvalue;
	const char *pvalue1;
	
	pvalue = ical_get_first_subvalue(piline);
	if (NULL == pvalue) {
		return FALSE;
	}
	pvalue1 = ical_get_first_paramval(piline, "VALUE");
	if (NULL == pvalue1 || 0 == strcasecmp(pvalue1, "DATE-TIME")) {
		if (FALSE == ical_parse_datetime(pvalue, pb_utc, pitime)) {
			if (NULL == pvalue1) {
				goto PARSE_DATE_VALUE;
			}
			return FALSE;
		}
		if (TRUE == *pb_utc) {
			if (FALSE == ical_itime_to_utc(NULL,
				*pitime, putc_time)) {
				return FALSE;
			}
		} else {
			if (FALSE == ical_itime_to_utc(
				ptz_component, *pitime, putc_time)) {
				return FALSE;
			}
		}
	} else if (0 == strcasecmp(pvalue1, "DATE")) {
PARSE_DATE_VALUE:
		memset(pitime, 0, sizeof(ICAL_TIME));
		if (FALSE == ical_parse_date(pvalue, &pitime->year,
			&pitime->month, &pitime->day)) {
			return FALSE;
		}
		if (FALSE == ical_itime_to_utc(
			ptz_component, *pitime, putc_time)) {
			return FALSE;
		}
		*pb_utc = FALSE;
	} else {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_parse_uid(ICAL_LINE *piline,
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
	static uint8_t arrayid[] = {
		0x04, 0x00, 0x00, 0x00, 0x82, 0x00, 0xE0, 0x00,
		0x74, 0xC5, 0xB7, 0x10, 0x1A, 0x82, 0xE0, 0x08};
	
	pvalue = ical_get_first_subvalue(piline);
	if (NULL == pvalue) {
		return TRUE;
	}
	tmp_len = strlen(pvalue);
	if (0 == strncasecmp(pvalue, "040000008200E00074C5B7101A82E008", 32)) {
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
	memcpy(globalobjectid.arrayid, arrayid, 16);
	globalobjectid.year = effective_itime.year;
	globalobjectid.month = effective_itime.month;
	globalobjectid.day = effective_itime.day;
	globalobjectid.creationtime = 0;
	globalobjectid.data.cb = 12 + tmp_len;
	globalobjectid.data.pb = alloc(globalobjectid.data.cb);
	if (NULL == globalobjectid.data.pb) {
		return FALSE;
	}
	memcpy(globalobjectid.data.pb, "\x76\x43\x61\x6c\x2d\x55\x69\x64\x01\x00\x00\x00", 12);
	memcpy(globalobjectid.data.pb + 12, pvalue, tmp_len);
MAKE_GLOBALOBJID:
	ext_buffer_push_init(&ext_push, tmp_buff, 1024, 0);
	if (EXT_ERR_SUCCESS != ext_buffer_push_globalobjectid(
		&ext_push, &globalobjectid)) {
		return FALSE;
	}
	tmp_bin.cb = ext_push.offset;
	tmp_bin.pb = tmp_buff;
	/* PidLidGlobalObjectId */
	lid = 0x00000003;
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_MEETING, &propname.guid);
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_BINARY;
	propval.pvalue = &tmp_bin;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
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
	tmp_bin.pb = tmp_buff;
	/* PidLidCleanGlobalObjectId */
	lid1 = 0x00000023;
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_MEETING, &propname.guid);
	propname.plid = &lid1;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_BINARY;
	propval.pvalue = &tmp_bin;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_location(
	ICAL_LINE *piline, INT_HASH_TABLE *phash,
	uint16_t *plast_propid, EXT_BUFFER_ALLOC alloc,
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
	
	pvalue = ical_get_first_subvalue(piline);
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
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_WSTRING;
	propval.pvalue = tmp_buff;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	pvalue = ical_get_first_paramval(piline, "ALTREP");
	if (NULL == pvalue) {
		return TRUE;
	}
	/* PidNameLocationUrl */
	propname.kind = KIND_NAME;
	rop_util_get_common_pset(PS_PUBLIC_STRINGS, &propname.guid);
	propname.pname = "urn:schemas:calendar:locationurl";
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_WSTRING;
	propval.pvalue = (void*)pvalue;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	if (NULL != pexception && NULL != pext_exception) {
		pexception->overrideflags |= OVERRIDEFLAG_LOCATION;
		pexception->location = alloc(tmp_len + 1);
		if (NULL == pexception->location) {
			return FALSE;
		}
		strcpy(pexception->location, tmp_buff);
		pext_exception->location = alloc(tmp_len + 1);
		if (NULL == pext_exception->location) {
			return FALSE;
		}
		strcpy(pext_exception->location, tmp_buff);
	}
	return TRUE;
}

static BOOL oxcical_parse_organizer(ICAL_LINE *piline,
	USERNAME_TO_ENTRYID username_to_entryid, MESSAGE_CONTENT *pmsg)
{
	void *pvalue;
	BINARY tmp_bin;
	char tmp_buff[1024];
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
	if (0 == strncasecmp(pvalue, "IPM.Schedule.Meeting.Resp.", 26)) {
		return TRUE;
	}
	paddress = ical_get_first_subvalue(piline);
	if (NULL != paddress) {
		if (0 == strncasecmp(paddress, "MAILTO:", 7)) {
			paddress += 7;
		} else {
			paddress = NULL;
		}
	}
	pdisplay_name = ical_get_first_paramval(piline, "CN");
	if (NULL != pdisplay_name) {
		propval.proptag = PROP_TAG_SENTREPRESENTINGNAME;
		propval.pvalue = (void*)pdisplay_name;
		if (FALSE == tpropval_array_set_propval(
			&pmsg->proplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_SENDERNAME;
		propval.pvalue = (void*)pdisplay_name;
		if (FALSE == tpropval_array_set_propval(
			&pmsg->proplist, &propval)) {
			return FALSE;
		}
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
	propval.pvalue = "SMTP";
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_SENTREPRESENTINGEMAILADDRESS;
	propval.pvalue = (void*)paddress;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_SENTREPRESENTINGSMTPADDRESS;
	propval.pvalue = (void*)paddress;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_SENTREPRESENTINGENTRYID;
	propval.pvalue = &tmp_bin;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_SENDERADDRESSTYPE;
	propval.pvalue = "SMTP";
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_SENDEREMAILADDRESS;
	propval.pvalue = (void*)paddress;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_SENDERSMTPADDRESS;
	propval.pvalue = (void*)paddress;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_SENDERENTRYID;
	propval.pvalue = &tmp_bin;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_parse_squence(ICAL_LINE *piline,
	INT_HASH_TABLE *phash, uint16_t *plast_propid,
	MESSAGE_CONTENT *pmsg)
{
	uint32_t tmp_int32;
	const char *pvalue;
	static uint32_t lid;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	pvalue = ical_get_first_subvalue(piline);
	if (NULL == pvalue) {
		return TRUE;
	}
	tmp_int32 = atoi(pvalue);
	/* PidLidAppointmentSequence */
	lid = 0x00008201;
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_LONG;
	propval.pvalue = &tmp_int32;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_busystatus(ICAL_LINE *piline,
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
	
	pvalue = ical_get_first_subvalue(piline);
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
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_LONG;
	propval.pvalue = &tmp_int32;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
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
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid1;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_LONG;
	propval.pvalue = &intented_val;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_transp(ICAL_LINE *piline,
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
	
	pvalue = ical_get_first_subvalue(piline);
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
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_LONG;
	propval.pvalue = &tmp_int32;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
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
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid1;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_LONG;
	propval.pvalue = &intented_val;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_status(ICAL_LINE *piline,
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
	
	pvalue = ical_get_first_subvalue(piline);
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
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_LONG;
	propval.pvalue = &tmp_int32;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
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
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid1;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_LONG;
	propval.pvalue = &intented_val;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_summary(
	ICAL_LINE *piline, MESSAGE_CONTENT *pmsg,
	EXT_BUFFER_ALLOC alloc, EXCEPTIONINFO *pexception,
	EXTENDEDEXCEPTION *pext_exception)
{
	int i;
	int tmp_len;
	uint32_t lid;
	const char *pvalue;
	char tmp_buff[1024];
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	pvalue = ical_get_first_subvalue(piline);
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
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	if (NULL != pexception && NULL != pext_exception) {
		pexception->overrideflags |= OVERRIDEFLAG_SUBJECT;
		pexception->subject = alloc(tmp_len + 1);
		if (NULL == pexception->subject) {
			return FALSE;
		}
		strcpy(pexception->subject, tmp_buff);
		pext_exception->subject = alloc(tmp_len + 1);
		if (NULL == pext_exception->subject) {
			return FALSE;
		}
		strcpy(pext_exception->subject, tmp_buff);
	}
	return TRUE;
}

static BOOL oxcical_parse_ownerapptid(
	ICAL_LINE *piline, MESSAGE_CONTENT *pmsg)
{
	uint32_t lid;
	uint32_t tmp_int32;
	const char *pvalue;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	pvalue = ical_get_first_subvalue(piline);
	if (NULL == pvalue) {
		return TRUE;
	}
	tmp_int32 = atoi(pvalue);
	propval.proptag = PROP_TAG_OWNERAPPOINTMENTID;
	propval.pvalue = &tmp_int32;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_parse_recurrence_id(ICAL_COMPONENT *ptz_component,
	ICAL_LINE *piline, INT_HASH_TABLE *phash, uint16_t *plast_propid,
	MESSAGE_CONTENT *pmsg)
{
	BOOL b_utc;
	time_t tmp_time;
	ICAL_TIME itime;
	uint64_t tmp_int64;
	static uint32_t lid;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	if (FALSE == oxcical_parse_dtvalue(ptz_component,
		piline, &b_utc, &itime, &tmp_time)) {
		return FALSE;
	}
	/* PidLidExceptionReplaceTime */
	lid = 0x00008228;
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16 |
									PROPVAL_TYPE_FILETIME;
	propval.pvalue = &tmp_int64;
	tmp_int64 = rop_util_unix_to_nttime(tmp_time);
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_parse_disallow_counter(ICAL_LINE *piline,
	INT_HASH_TABLE *phash, uint16_t *plast_propid,
	MESSAGE_CONTENT *pmsg)
{
	uint8_t tmp_byte;
	const char *pvalue;
	static uint32_t lid;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	pvalue = ical_get_first_subvalue(piline);
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
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_BYTE;
	propval.pvalue = &tmp_byte;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	return TRUE;
}

static int oxcical_cmp_date(const void *pdate1, const void *pdate2)
{
	return *(uint32_t*)pdate1 - *(uint32_t*)pdate2;
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
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid1;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		ext_buffer_push_free(&ext_push);
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_BINARY;
	propval.pvalue = &tmp_bin;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
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
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid2;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_FILETIME;
	propval.pvalue = &nt_time;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	nt_time = papprecurr->recurrencepattern.startdate;
	nt_time *= 600000000;
	/* PidLidClipStart */
	lid3 = 0x00008235;
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	propname.plid = &lid3;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_FILETIME;
	propval.pvalue = &nt_time;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	return TRUE;
}

static int oxcical_cmp_exception(
	const void *pexception1, const void *pexception2)
{
	return ((EXCEPTIONINFO*)pexception1)->startdatetime -
			((EXCEPTIONINFO*)pexception2)->startdatetime;
}

static int oxcical_cmp_ext_exception(
	const void *pext_exception1, const void *pext_exception2)
{
	return ((EXTENDEDEXCEPTION*)pext_exception1)->startdatetime -
			((EXTENDEDEXCEPTION*)pext_exception2)->startdatetime;
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
		propid = proptag >> 16;
		if (0 == (propid & 0x8000)) {
			continue;
		}
		ppropid = int_hash_query(phash, propid);
		if (NULL == ppropid || 0 == *ppropid) {
			tpropval_array_remove_propval(pproplist, proptag);
			i --;
			continue;
		}
		proptag = *ppropid;
		proptag <<= 16;
		pproplist->ppropval[i].proptag &= 0xFFFF;
		pproplist->ppropval[i].proptag |= proptag;
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
	INT_HASH_TABLE *phash1;
	PROPERTY_NAME *ppropname;
	PROPNAME_ARRAY propnames;
	
	propids.count = 0;
	propids.ppropid = alloc(sizeof(uint16_t)*phash->item_num);
	if (NULL == propids.ppropid) {
		return FALSE;
	}
	propnames.count = 0;
	propnames.ppropname = alloc(sizeof(PROPERTY_NAME)*phash->item_num);
	if (NULL == propnames.ppropname) {
		return FALSE;
	}
	iter = int_hash_iter_init(phash);
	for (int_hash_iter_begin(iter); !int_hash_iter_done(iter);
		int_hash_iter_forward(iter)) {
		ppropname = int_hash_iter_get_value(iter, &tmp_int);
		propids.ppropid[propids.count] = tmp_int;
		propnames.ppropname[propnames.count] = *ppropname;
		propids.count ++;
		propnames.count ++;
	}
	int_hash_iter_free(iter);
	if (FALSE == get_propids(&propnames, &propids1)) {
		return FALSE;
	}
	phash1 = int_hash_init(0x1000, sizeof(uint16_t), NULL);
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

static BOOL oxcical_parse_exceptional_attachment(
	ATTACHMENT_CONTENT *pattachment, ICAL_COMPONENT *pcomponent,
	ICAL_TIME start_itime, ICAL_TIME end_itime, MESSAGE_CONTENT *pmsg)
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
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_RENDERINGPOSITION;
	propval.pvalue = &tmp_int32;
	tmp_int32 = 0xFFFFFFFF;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_DISPLAYNAME;
	propval.pvalue = tpropval_array_get_propval(
		&pattachment->pembedded->proplist, PROP_TAG_SUBJECT);
	if (NULL != propval.pvalue) {
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			return FALSE;
		}
	}
	if (FALSE == ical_itime_to_utc(NULL,
		start_itime, &tmp_time)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_EXCEPTIONSTARTTIME;
	propval.pvalue = &tmp_int64;
	tmp_int64 = rop_util_unix_to_nttime(tmp_time);
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	if (FALSE == ical_itime_to_utc(NULL,
		end_itime, &tmp_time)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_EXCEPTIONENDTIME;
	propval.pvalue = &tmp_int64;
	tmp_int64 = rop_util_unix_to_nttime(tmp_time);
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_ATTACHENCODING;
	propval.pvalue = &tmp_bin;
	tmp_bin.cb = 0;
	tmp_bin.pb = NULL;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_ATTACHMENTFLAGS;
	propval.pvalue = &tmp_int32;
	tmp_int32 = 0x00000002;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_ATTACHMENTLINKID;
	propval.pvalue = &tmp_int32;
	tmp_int32 = 0x00000000;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_ATTACHFLAGS;
	propval.pvalue = &tmp_int32;
	tmp_int32 = 0x00000000;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_ATTACHMENTHIDDEN;
	propval.pvalue = &tmp_byte;
	tmp_byte = 1;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_ATTACHMENTCONTACTPHOTO;
	propval.pvalue = &tmp_byte;
	tmp_byte = 0;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcical_parse_attachment(
	ICAL_LINE *piline, int count, MESSAGE_CONTENT *pmsg)
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
	
	pvalue = ical_get_first_paramval(piline, "VALUE");
	if (NULL == pvalue) {
		pvalue = ical_get_first_subvalue(piline);
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
			tmp_bin.cb = snprintf(tmp_buff, 1024,
				"[InternetShortcut]\r\nURL=%s", pvalue);
			tmp_bin.pb = tmp_buff;
			propval.proptag = PROP_TAG_ATTACHDATABINARY;
			propval.pvalue = &tmp_bin;
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				return FALSE;
			}
			propval.proptag = PROP_TAG_ATTACHENCODING;
			propval.pvalue = &tmp_bin;
			tmp_bin.cb = 0;
			tmp_bin.pb = NULL;
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				return FALSE;
			}
			propval.proptag = PROP_TAG_ATTACHEXTENSION;
			propval.pvalue = ".URL";
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				return FALSE;
			}
			pvalue1 = strrchr(pvalue, '/');
			if (NULL == pvalue1) {
				pvalue1 = pvalue;
			}
			snprintf(tmp_buff, 256, "%s.url", pvalue1);
			propval.proptag = PROP_TAG_ATTACHLONGFILENAME;
			propval.pvalue = tmp_buff;
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				return FALSE;
			}
			propval.proptag = PROP_TAG_DISPLAYNAME;
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				return FALSE;
			}
			propval.proptag = PROP_TAG_ATTACHMETHOD;
			propval.pvalue = &tmp_int32;
			tmp_int32 = ATTACH_METHOD_BY_VALUE;
			pvalue1 = ical_get_first_paramval(piline, "FMTYPE");
			if (NULL != pvalue1) {
				propval.proptag = PROP_TAG_ATTACHMIMETAG;
				propval.pvalue = (void*)pvalue1;
				if (FALSE == tpropval_array_set_propval(
					&pattachment->proplist, &propval)) {
					return FALSE;
				}
			}
			propval.proptag = PROP_TAG_ATTACHFLAGS;
			propval.pvalue = &tmp_int32;
			tmp_int32 = 0;
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				return FALSE;
			}
			propval.proptag = PROP_TAG_ATTACHMENTLINKID;
			propval.pvalue = &tmp_int32;
			tmp_int32 = 0;
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				return FALSE;
			}
			propval.proptag = PROP_TAG_ATTACHMENTCONTACTPHOTO;
			propval.pvalue = &tmp_byte;
			tmp_byte = 0;
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				return FALSE;
			}
			propval.proptag = PROP_TAG_ATTACHMENTCONTACTPHOTO;
			propval.pvalue = &tmp_byte;
			tmp_byte = 0;
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				return FALSE;
			}
			propval.proptag = PROP_TAG_EXCEPTIONSTARTTIME;
			propval.pvalue = &tmp_int64;
			tmp_int64 = 0x0CB34557A3DD4000;
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				return FALSE;
			}
			propval.proptag = PROP_TAG_EXCEPTIONENDTIME;
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				return FALSE;
			}
			propval.proptag = PROP_TAG_RENDERINGPOSITION;
			propval.pvalue = &tmp_int32;
			tmp_int32 = 0xFFFFFFFF;
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				return FALSE;
			}
		}
	} else if (0 == strcasecmp(pvalue, "BINARY")) {
		pvalue = ical_get_first_paramval(piline, "ENCODING");
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
		pvalue = ical_get_first_subvalue(piline);
		if (NULL != pvalue) {
			tmp_int32 = strlen(pvalue);
			tmp_bin.pb = malloc(tmp_int32);
			if (NULL == tmp_bin.pb) {
				return FALSE;
			}
			if (0 != decode64(pvalue, tmp_int32,
				tmp_bin.pb, &decode_len)) {
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
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			return FALSE;
		}
		if (NULL != tmp_bin.pb) {
			free(tmp_bin.pb);
		}
		propval.proptag = PROP_TAG_ATTACHENCODING;
		propval.pvalue = &tmp_bin;
		tmp_bin.cb = 0;
		tmp_bin.pb = NULL;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			return FALSE;
		}
		pvalue = ical_get_first_paramval(piline, "X-FILENAME");
		if (NULL == pvalue) {
			pvalue = ical_get_first_paramval(piline, "FILENAME");
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
		propval.pvalue = (void*)pvalue1;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_ATTACHLONGFILENAME;
		propval.pvalue = (void*)pvalue;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_DISPLAYNAME;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_ATTACHMETHOD;
		propval.pvalue = &tmp_int32;
		tmp_int32 = ATTACH_METHOD_BY_VALUE;
		pvalue1 = ical_get_first_paramval(piline, "FMTYPE");
		if (NULL != pvalue1) {
			propval.proptag = PROP_TAG_ATTACHMIMETAG;
			propval.pvalue = (void*)pvalue1;
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				return FALSE;
			}
		}
		propval.proptag = PROP_TAG_ATTACHFLAGS;
		propval.pvalue = &tmp_int32;
		tmp_int32 = 0;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_ATTACHMENTLINKID;
		propval.pvalue = &tmp_int32;
		tmp_int32 = 0;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_ATTACHMENTCONTACTPHOTO;
		propval.pvalue = &tmp_byte;
		tmp_byte = 0;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_ATTACHMENTCONTACTPHOTO;
		propval.pvalue = &tmp_byte;
		tmp_byte = 0;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_EXCEPTIONSTARTTIME;
		propval.pvalue = &tmp_int64;
		tmp_int64 = 0x0CB34557A3DD4000;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_EXCEPTIONENDTIME;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_RENDERINGPOSITION;
		propval.pvalue = &tmp_int32;
		tmp_int32 = 0xFFFFFFFF;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			return FALSE;
		}
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
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	propname.plid = &lid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_LONG;
	propval.pvalue = &reminder_delta;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	/* PidLidReminderTime */
	lid1 = 0x00008502;
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	propname.plid = &lid1;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_FILETIME;
	propval.pvalue = &tmp_int64;
	tmp_int64 = rop_util_unix_to_nttime(start_time);
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	/* PidLidReminderSignalTime */
	lid2 = 0x00008560;
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	propname.plid = &lid2;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_FILETIME;
	propval.pvalue = &tmp_int64;
	tmp_int64 = rop_util_unix_to_nttime(
		start_time - reminder_delta*60);
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	/* PidLidReminderSet */
	lid3 = 0x00008503;
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	propname.plid = &lid3;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	propval.proptag |= PROPVAL_TYPE_BYTE;
	propval.pvalue = &tmp_byte;
	tmp_byte = 1;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcical_import_internal(
	const char *str_zone, const char *method, BOOL b_proposal,
	uint16_t calendartype, ICAL *pical, DOUBLE_LIST *pevent_list,
	EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
	USERNAME_TO_ENTRYID username_to_entryid, MESSAGE_CONTENT *pmsg,
	ICAL_TIME *pstart_itime, ICAL_TIME *pend_itime,
	EXCEPTIONINFO *pexception, EXTENDEDEXCEPTION *pext_exception)
{
	int i;
	BOOL b_utc;
	BOOL b_alarm;
	BOOL b_allday;
	long duration;
	int tmp_count;
	BOOL b_utc_end;
	BINARY tmp_bin;
	time_t tmp_time;
	time_t end_time;
	ICAL_TIME itime;
	BOOL b_utc_start;
	const char *ptzid;
	ICAL_LINE *piline;
	time_t start_time;
	uint32_t tmp_int32;
	uint64_t tmp_int64;
	const char *pvalue;
	const char *pvalue1;
	ICAL_TIME end_itime;
	char tmp_buff[1280];
	DOUBLE_LIST tmp_list;
	uint16_t last_propid;
	INT_HASH_TABLE *phash;
	ICAL_TIME start_itime;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE tmp_node;
	MESSAGE_CONTENT *pembedded;
	ICAL_COMPONENT *pmain_event;
	uint32_t deleted_dates[1024];
	uint32_t modified_dates[1024];
	ICAL_COMPONENT *ptz_component;
	ATTACHMENT_LIST *pattachments;
	EXCEPTIONINFO exceptions[1024];
	ATTACHMENT_CONTENT *pattachment;
	ICAL_COMPONENT *palarm_component;
	EXTENDEDEXCEPTION ext_exceptions[1024];
	APPOINTMENTRECURRENCEPATTERN apprecurr;
	
	
	if (1 == double_list_get_nodes_num(pevent_list)) {
		pnode = double_list_get_head(pevent_list);
		pmain_event = pnode->pdata;
	} else {
		pmain_event = NULL;
		for (pnode=double_list_get_head(pevent_list); NULL!=pnode;
			pnode=double_list_get_after(pevent_list, pnode)) {
			piline = ical_get_line(pnode->pdata, "RECURRENCE-ID");
			if (NULL == piline) {
				if (NULL != pmain_event) {
					return FALSE;
				}
				pmain_event = pnode->pdata;
				if (NULL == ical_get_line(pmain_event, "X-MICROSOFT-RRULE")
					&& NULL == ical_get_line(pmain_event, "RRULE")) {
					return FALSE;
				}
			} else {
				if (NULL != ical_get_line(pnode->pdata, "X-MICROSOFT-RRULE")
					|| NULL != ical_get_line(pnode->pdata, "RRULE")) {
					return FALSE;
				}
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
	phash = int_hash_init(0x1000, sizeof(PROPERTY_NAME), NULL);
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
	
	piline = ical_get_line(pmain_event, "CATEGORIS");
	if (NULL != piline) {
		if (FALSE == oxcical_parse_categoris(
			piline, phash, &last_propid, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	piline = ical_get_line(pmain_event, "CLASS");
	if (NULL != piline) {
		if (FALSE == oxcical_parse_class(piline, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	} else {
		propval.proptag = PROP_TAG_SENSITIVITY;
		propval.pvalue = &tmp_int32;
		tmp_int32 = 0;
		if (FALSE == tpropval_array_set_propval(
			&pmsg->proplist, &propval)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	if (NULL != method && (0 == strcasecmp(method, "REPLY") ||
		0 == strcasecmp(method, "COUNTER"))) {
		piline = ical_get_line(pmain_event, "COMMENT");
	} else {
		piline = ical_get_line(pmain_event, "DESCRIPTION");
	}
	if (NULL != piline) {
		if (FALSE == oxcical_parse_body(piline, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	piline = ical_get_line(pmain_event, "X-ALT-DESC");
	if (NULL != piline) {
		pvalue = ical_get_first_paramval(piline, "FMTTYPE");
		if (NULL != pvalue && 0 == strcasecmp(pvalue, "text/html")) {
			if (FALSE == oxcical_parse_html(piline, pmsg)) {
				int_hash_free(phash);
				return FALSE;
			}
		}
	}
	
	b_allday = FALSE;
	piline = ical_get_line(pmain_event,
		"X-MICROSOFT-MSNCALENDAR-ALLDAYEVENT");
	if (NULL == piline) {
		piline = ical_get_line(pmain_event,
			"X-MICROSOFT-CDO-ALLDAYEVENT");
	}
	if (NULL != piline) {
		pvalue = ical_get_first_subvalue(piline);
		if (NULL != pvalue && 0 == strcasecmp(pvalue, "TRUE")) {
			b_allday = TRUE;
		}
	}
	
	piline = ical_get_line(pmain_event, "DTSTAMP");
	if (NULL != piline) {
		if (FALSE == oxcical_parse_dtstamp(piline,
			method, phash, &last_propid, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	piline = ical_get_line(pmain_event, "DTSTART");
	if (NULL == piline) {
		int_hash_free(phash);
		return FALSE;
	}
	pvalue1 = ical_get_first_paramval(piline, "VALUE");
	ptzid = ical_get_first_paramval(piline, "TZID");
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
	
	piline = ical_get_line(pmain_event, "DTEND");
	if (NULL != piline) {
		pvalue = ical_get_first_paramval(piline, "TZID");
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
			int_hash_free(phash);
			return FALSE;
		}
	} else {
		piline = ical_get_line(pmain_event, "DURATION");
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
			pvalue = ical_get_first_subvalue(piline);
			if (NULL == pvalue || FALSE == ical_parse_duration(
				pvalue, &duration) || duration < 0) {
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
		if (FALSE == b_utc_start && FALSE == b_utc_end &&
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
	piline = ical_get_line(pmain_event, "RECURRENCE-ID");
	if (NULL != piline) {
		if (NULL != pexception && NULL != pext_exception) {
			if (FALSE == oxcical_parse_recurrence_id(ptz_component,
				piline, phash, &last_propid, pmsg)) {
				int_hash_free(phash);
				return FALSE;
			}
		}
		pvalue = ical_get_first_paramval(piline, "TZID");
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
			if (FALSE == b_utc && (0 != itime.hour || 0 != itime.minute
				|| 0 != itime.second || 0 != itime.leap_second)) {
				int_hash_free(phash);
				return FALSE;
			}
		}
	}
	
	piline = ical_get_line(pmain_event, "UID");
	if (NULL != piline) {
		if (FALSE == oxcical_parse_uid(piline, itime,
			alloc, phash, &last_propid, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	piline = ical_get_line(pmain_event, "LOCATION");
	if (NULL != piline) {
		if (FALSE == oxcical_parse_location(piline, phash,
			&last_propid, alloc, pmsg, pexception, pext_exception)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	piline = ical_get_line(pmain_event, "ORGANIZER");
	if (NULL != piline) {
		if (FALSE == oxcical_parse_organizer(
			piline, username_to_entryid, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	piline = ical_get_line(pmain_event, "X-MICROSOFT-CDO-IMPORTANCE");
	if (NULL == piline) {
		piline = ical_get_line(pmain_event,
			"X-MICROSOFT-MSNCALENDAR-IMPORTANCE");
	}
	if (NULL != piline) {
		pvalue = ical_get_first_subvalue(piline);
		if (NULL != pvalue) {
			tmp_int32 = atoi(pvalue);
			if (0 == tmp_int32 || 1 == tmp_int32 || 2 == tmp_int32) {
				propval.proptag = PROP_TAG_IMPORTANCE;
				propval.pvalue = &tmp_int32;
				if (FALSE == tpropval_array_set_propval(
					&pmsg->proplist, &propval)) {
					int_hash_free(phash);
					return FALSE;
				}
			}
		}
	} else {
		piline = ical_get_line(pmain_event, "PRIORITY");
		if (NULL != piline) {
			pvalue = ical_get_first_subvalue(piline);
			if (NULL != pvalue) {
				propval.proptag = PROP_TAG_IMPORTANCE;
				propval.pvalue = &tmp_int32;
				switch (atoi(pvalue)) {
				case 1:
				case 2:
				case 3:
				case 4:
					tmp_int32 = 2;
					if (FALSE == tpropval_array_set_propval(
						&pmsg->proplist, &propval)) {
						int_hash_free(phash);
						return FALSE;
					}
					break;
				case 5:
					tmp_int32 = 1;
					if (FALSE == tpropval_array_set_propval(
						&pmsg->proplist, &propval)) {
						int_hash_free(phash);
						return FALSE;
					}
					break;
				case 6:
				case 7:
				case 8:
				case 9:
					tmp_int32 = 0;
					if (FALSE == tpropval_array_set_propval(
						&pmsg->proplist, &propval)) {
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
		if (FALSE == tpropval_array_set_propval(
			&pmsg->proplist, &propval)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	piline = ical_get_line(pmain_event, "X-MICROSOFT-CDO-APPT-SEQUENCE");
	if (NULL == piline) {
		piline = ical_get_line(pmain_event, "SEQUENCE");
	}
	if (NULL != piline) {
		if (FALSE == oxcical_parse_squence(
			piline, phash, &last_propid, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	if (0 == strcasecmp(method, "REQUEST")) {
		if (NULL != ical_get_line(pmain_event,
			"X-MICROSOFT-CDO-INTENDEDSTATUS") ||
			NULL != ical_get_line(pmain_event,
			"X-MICROSOFT-MSNCALENDAR-INTENDEDSTATUS")) {
			tmp_int32 = 1;
		} else {
			tmp_int32 = 2;
		}
	} else {
		tmp_int32 = 0;
	}
	
	piline = ical_get_line(pmain_event, "X-MICROSOFT-CDO-BUSYSTATUS");
	if (NULL == piline) {
		piline = ical_get_line(pmain_event,
			"X-MICROSOFT-MSNCALENDAR-BUSYSTATUS");
	}
	if (NULL != piline) {
		if (FALSE == oxcical_parse_busystatus(piline,
			tmp_int32, phash, &last_propid, pmsg, pexception)) {
			int_hash_free(phash);
			return FALSE;
		}
	} else {
		piline = ical_get_line(pmain_event, "TRANSP");
		if (NULL != piline) {
			if (FALSE == oxcical_parse_transp(piline,
				tmp_int32, phash, &last_propid, pmsg, pexception)) {
				int_hash_free(phash);
				return FALSE;
			}
		} else {
			piline = ical_get_line(pmain_event, "STATUS");
			if (NULL != piline) {
				if (FALSE == oxcical_parse_status(piline,
					tmp_int32, phash, &last_propid, pmsg, pexception)) {
					int_hash_free(phash);
					return FALSE;
				}
			}
		}
	}
	
	piline = ical_get_line(pmain_event, "X-MICROSOFT-CDO-OWNERAPPTID");
	if (NULL != piline) {
		if (FALSE == oxcical_parse_ownerapptid(piline, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	piline = ical_get_line(pmain_event, "X-MICROSOFT-DISALLOW-COUNTER");
	if (NULL != piline) {
		if (FALSE == oxcical_parse_disallow_counter(
			piline, phash, &last_propid, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	piline = ical_get_line(pmain_event, "SUMMARY");
	if (NULL != piline) {
		if (FALSE == oxcical_parse_summary(piline,
			pmsg, alloc, pexception, pext_exception)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	piline = ical_get_line(pmain_event, "RRULE");
	if (NULL == piline) {
		piline = ical_get_line(pmain_event, "X-MICROSOFT-RRULE");
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
		piline = ical_get_line(pmain_event, "EXDATE");
		if (NULL == piline) {
			piline = ical_get_line(pmain_event, "X-MICROSOFT-EXDATE");
		}
		if (NULL != piline) {
			if (FALSE == oxcical_parse_dates(ptz_component, piline,
				&apprecurr.recurrencepattern.deletedinstancecount,
				deleted_dates)) {
				int_hash_free(phash);
				return FALSE;
			}
		}
		piline = ical_get_line(pmain_event, "RDATE");
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
		
		if (double_list_get_nodes_num(pevent_list) > 1) {
			pattachments = attachment_list_init();
			if (NULL == pattachments) {
				int_hash_free(phash);
				return FALSE;
			}
			message_content_set_attachments_internal(pmsg, pattachments);
		}
		for (pnode=double_list_get_head(pevent_list); NULL!=pnode;
			pnode=double_list_get_after(pevent_list, pnode)) {
			if (pnode->pdata == pmain_event) {
				continue;
			}
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
			attachment_content_set_embeded_internal(pattachment, pembedded);
			propval.proptag = PROP_TAG_MESSAGECLASS;
			propval.pvalue = "IPM.OLE.CLASS.{00061055-0000-0000-C000-000000000046}";
			if (FALSE == tpropval_array_set_propval(
				&pembedded->proplist, &propval)) {
				int_hash_free(phash);
				return FALSE;
			}
			
			double_list_init(&tmp_list);
			double_list_append_as_tail(&tmp_list, &tmp_node);
			tmp_node.pdata = pnode->pdata;
			if (FALSE == oxcical_import_internal(str_zone, method,
				FALSE, calendartype, pical, &tmp_list, alloc,
				get_propids, username_to_entryid, pembedded, &start_itime,
				&end_itime, exceptions + apprecurr.exceptioncount,
				ext_exceptions + apprecurr.exceptioncount)) {
				int_hash_free(phash);
				return FALSE;
			}
			
			if (FALSE == oxcical_parse_exceptional_attachment(
				pattachment, pnode->pdata, start_itime,
				end_itime, pmsg)) {
				int_hash_free(phash);
				return FALSE;
			}
			
			piline = ical_get_line(pnode->pdata, "RECURRENCE-ID");
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
	for (pnode=double_list_get_head(&pmain_event->line_list); NULL!=pnode;
		pnode=double_list_get_after(&pmain_event->line_list, pnode)) {
		piline = (ICAL_LINE*)pnode->pdata;
		if (0 != strcasecmp(piline->name, "ATTACH")) {
			continue;
		}
		tmp_count ++;
		if (FALSE == oxcical_parse_attachment(piline, tmp_count, pmsg)) {
			int_hash_free(phash);
			return FALSE;
		}
	}
	
	b_alarm = FALSE;
	pnode = double_list_get_head(&pmain_event->component_list);
	if (NULL != pnode) {
		palarm_component = (ICAL_COMPONENT*)pnode->pdata;
		if (0 == strcasecmp(palarm_component->name, "VALARM")) {
			b_alarm = TRUE;
			piline = ical_get_line(palarm_component, "TRIGGER");
			if (NULL == piline || NULL == (pvalue =
				ical_get_first_subvalue(piline))) {
				if (FALSE == b_allday) {
					tmp_int32 = 15;
				} else {
					tmp_int32 = 1080;
				}
			} else {
				pvalue1 = ical_get_first_paramval(piline, "RELATED");
				if (NULL == pvalue1) {
					pvalue1 = ical_get_first_paramval(piline, "VALUE");
					if ((NULL == pvalue1 || 0 == strcasecmp(pvalue1,
						"DATE-TIME")) && TRUE == ical_datetime_to_utc(
						ptz_component, pvalue, &tmp_time)) {
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
						FALSE == ical_parse_duration(pvalue, &duration)) {
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

static BOOL oxcical_import_events(
	const char *str_zone, uint16_t calendartype, ICAL *pical,
	DOUBLE_LIST *pevents_list, EXT_BUFFER_ALLOC alloc,
	GET_PROPIDS get_propids, USERNAME_TO_ENTRYID username_to_entryid,
	MESSAGE_CONTENT *pmsg)
{
	TAGGED_PROPVAL propval;
	UID_EVENTS *puid_events;
	DOUBLE_LIST_NODE *pnode;
	MESSAGE_CONTENT *pembedded;
	ATTACHMENT_LIST *pattachments;
	ATTACHMENT_CONTENT *pattachment;
	
	pattachments = attachment_list_init();
	if (NULL == pattachments) {
		return FALSE;
	}
	message_content_set_attachments_internal(pmsg, pattachments);
	for (pnode=double_list_get_head(pevents_list); NULL!=pnode;
		pnode=double_list_get_after(pevents_list, pnode)) {
		puid_events = (UID_EVENTS*)pnode->pdata;
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
		attachment_content_set_embeded_internal(pattachment, pembedded);
		propval.proptag = PROP_TAG_MESSAGECLASS;
		propval.pvalue = "IPM.Appointment";
		if (FALSE == tpropval_array_set_propval(
			&pembedded->proplist, &propval)) {
			return FALSE;
		}
		if (FALSE == oxcical_import_internal(str_zone, "PUBLISH",
			FALSE, calendartype, pical, &puid_events->list, alloc,
			get_propids, username_to_entryid, pembedded, NULL,
			NULL, NULL, NULL)) {
			return FALSE;
		}
	}
	return TRUE;
}

static void oxcical_clear_event_uid_list(DOUBLE_LIST *plist)
{
	UID_EVENTS *puid_events;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	
	while (pnode=double_list_get_from_head(plist)) {
		puid_events = pnode->pdata;
		while (pnode1=double_list_get_from_head(&puid_events->list)) {
			free(pnode1);
		}
		double_list_free(&puid_events->list);
		free(puid_events);
	}
}

static BOOL oxcical_classify_calendar(
	ICAL *pical, DOUBLE_LIST *pevent_uid_list)
{
	const char *puid;
	ICAL_LINE *piline;
	UID_EVENTS *puid_events;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	DOUBLE_LIST_NODE *pnode2;
	ICAL_COMPONENT *pcomponent;
	
	for (pnode=double_list_get_head(&pical->component_list); NULL!=pnode;
		pnode=double_list_get_after(&pical->component_list, pnode)) {
		pcomponent = (ICAL_COMPONENT*)pnode->pdata;
		if (0 != strcasecmp(pcomponent->name, "VEVENT")) {
			continue;
		}
		piline = ical_get_line(pcomponent, "UID");
		if (NULL == piline) {
			puid = NULL;
			goto NEW_UID_EVENTS;
		}
		puid = ical_get_first_subvalue(piline);
		if (NULL == puid) {
			goto NEW_UID_EVENTS;
		}
		for (pnode1=double_list_get_head(pevent_uid_list); NULL!=pnode1;
			pnode1=double_list_get_after(pevent_uid_list, pnode1)) {
			puid_events = (UID_EVENTS*)pnode1->pdata;
			if (NULL == puid_events->puid) {
				continue;
			}
			if (0 == strcmp(puid_events->puid, puid)) {
				break;
			}
		}
		if (NULL != pnode1) {
			goto APPEND_EVENT;
		}
NEW_UID_EVENTS:
		puid_events = malloc(sizeof(UID_EVENTS));
		if (NULL == puid_events) {
			return FALSE;
		}
		puid_events->node.pdata = puid_events;
		puid_events->puid = puid;
		double_list_init(&puid_events->list);
		double_list_append_as_tail(pevent_uid_list, &puid_events->node);
APPEND_EVENT:
		pnode2 = malloc(sizeof(DOUBLE_LIST_NODE));
		if (NULL == pnode2) {
			return FALSE;
		}
		pnode2->pdata = pcomponent;
		double_list_append_as_tail(&puid_events->list, pnode2);
	}
	return TRUE;
}

static const char* oxcical_get_partstat(const DOUBLE_LIST *pevents_list)
{
	ICAL_LINE *piline;
	UID_EVENTS *puid_events;
	DOUBLE_LIST_NODE *pnode;
	
	pnode = double_list_get_head((DOUBLE_LIST*)pevents_list);
	if (NULL == pnode) {
		return NULL;
	}
	puid_events = (UID_EVENTS*)pnode->pdata;
	for (pnode=double_list_get_head(&puid_events->list); NULL!=pnode;
		pnode=double_list_get_after(&puid_events->list, pnode)) {
		piline = ical_get_line(pnode->pdata, "ATTENDEE");
		if (NULL != piline) {
			return ical_get_first_paramval(piline, "PARTSTAT");
		}
	}
	return NULL;
}

static uint32_t oxcical_get_calendartype(ICAL_LINE *piline)
{
	const char *pvalue;
	
	if (NULL == piline) {
		return CALENDARTYPE_DEFAULT;
	}
	pvalue = ical_get_first_subvalue(piline);
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
	ICAL_LINE *piline;
	const char *pvalue;
	const char *pvalue1;
	uint16_t calendartype;
	MESSAGE_CONTENT *pmsg;
	TAGGED_PROPVAL propval;
	DOUBLE_LIST events_list;
	UID_EVENTS *puid_events;
	DOUBLE_LIST_NODE *pnode;
	
	b_proposal = FALSE;
	pmsg = message_content_init();
	if (NULL == pmsg) {
		return NULL;
	}
	piline = ical_get_line((ICAL*)pical, "X-MICROSOFT-CALSCALE");
	calendartype = oxcical_get_calendartype(piline);
	double_list_init(&events_list);
	if (FALSE == oxcical_classify_calendar((ICAL*)pical, &events_list)
		|| 0 == double_list_get_nodes_num(&events_list)) {
		goto IMPORT_FAILURE;
	}
	propval.proptag = PROP_TAG_MESSAGECLASS;
	piline = ical_get_line((ICAL_COMPONENT*)pical, "METHOD");
	propval.pvalue = "IPM.Appointment";
	if (NULL != piline) {
		pvalue = ical_get_first_subvalue(piline);
		if (NULL != pvalue) {
			if (0 == strcasecmp(pvalue, "PUBLISH")) {
				if (double_list_get_nodes_num(&events_list) > 1) {
					if (FALSE == oxcical_import_events(str_zone,
						calendartype, (ICAL*)pical, &events_list, alloc,
						get_propids, username_to_entryid, pmsg)) {
						goto IMPORT_FAILURE;
					}
					oxcical_clear_event_uid_list(&events_list);
					double_list_free(&events_list);
					return pmsg;
				}
				propval.pvalue = "IPM.Appointment";
			} else if (0 == strcasecmp(pvalue, "REQUEST")) {
				if (1 != double_list_get_nodes_num(&events_list)) {
					goto IMPORT_FAILURE;
				}
				propval.pvalue = "IPM.Schedule.Meeting.Request";
			} else if (0 == strcasecmp(pvalue, "REPLY")) {
				if (1 != double_list_get_nodes_num(&events_list)) {
					goto IMPORT_FAILURE;
				}
				pvalue1 = oxcical_get_partstat(&events_list);
				if (NULL != pvalue1) {
					if (0 == strcasecmp(pvalue1, "ACCEPTED")) {
						propval.pvalue = "IPM.Schedule.Meeting.Resp.Pos";
					} else if (0 == strcasecmp(pvalue1, "TENTATIVE")) {
						propval.pvalue = "IPM.Schedule.Meeting.Resp.Tent";
					} else if (0 == strcasecmp(pvalue1, "DECLINED")) {
						propval.pvalue = "IPM.Schedule.Meeting.Resp.Neg";
					}
				}
			} else if (0 == strcasecmp(pvalue, "COUNTER")) {
				if (1 != double_list_get_nodes_num(&events_list)) {
					goto IMPORT_FAILURE;
				}
				pvalue1 = oxcical_get_partstat(&events_list);
				if (NULL != pvalue1 && 0 == strcasecmp(pvalue1, "TENTATIVE")) {
					propval.pvalue = "IPM.Schedule.Meeting.Resp.Tent";
					b_proposal = TRUE;
				}
			} else if (0 == strcasecmp(pvalue, "CANCEL")) {
				propval.pvalue = "IPM.Schedule.Meeting.Canceled";
			}
		}
	} else {
		if (double_list_get_nodes_num(&events_list) > 1) {
			if (FALSE == oxcical_import_events(str_zone,
				calendartype, (ICAL*)pical, &events_list, alloc,
				get_propids, username_to_entryid, pmsg)) {
				goto IMPORT_FAILURE;
			}
			oxcical_clear_event_uid_list(&events_list);
			double_list_free(&events_list);
			return pmsg;
		}
	}
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		goto IMPORT_FAILURE;
	}
	pnode = double_list_get_head(&events_list);
	puid_events = (UID_EVENTS*)pnode->pdata;
	if (TRUE == oxcical_import_internal(str_zone, pvalue,
		b_proposal, calendartype, (ICAL*)pical, &puid_events->list,
		alloc, get_propids, username_to_entryid, pmsg, NULL, NULL,
		NULL, NULL)) {
		oxcical_clear_event_uid_list(&events_list);
		double_list_free(&events_list);
		return pmsg;
	}
IMPORT_FAILURE:
	oxcical_clear_event_uid_list(&events_list);
	double_list_free(&events_list);
	message_content_free(pmsg);
	return NULL;
}

static ICAL_COMPONENT* oxcical_export_timezone(ICAL *pical,
	int year, const char *tzid, TIMEZONESTRUCT *ptzstruct)
{
	int day;
	int order;
	int utc_offset;
	ICAL_LINE *piline;
	ICAL_VALUE *pivalue;
	char tmp_buff[1024];
	ICAL_COMPONENT *pcomponent;
	ICAL_COMPONENT *pcomponent1;
	
	pcomponent = ical_new_component("VTIMEZONE");
	if (NULL == pcomponent) {
		return NULL;
	}
	ical_append_component(pical, pcomponent);
	piline = ical_new_simple_line("TZID", tzid);
	if (NULL == piline) {
		return NULL;
	}
	ical_append_line(pcomponent, piline);
	/* STANDARD component */
	pcomponent1 = ical_new_component("STANDARD");
	if (NULL == pcomponent1) {
		return NULL;
	}
	ical_append_component(pcomponent, pcomponent1);
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
	ical_append_line(pcomponent1, piline);
	if (0 != ptzstruct->daylightdate.month) {
		if (0 == ptzstruct->standarddate.year) {
			piline = ical_new_line("RRULE");
			if (NULL == piline) {
				return NULL;
			}
			ical_append_line(pcomponent1, piline);
			pivalue = ical_new_value("FREQ");
			if (NULL == pivalue) {
				return NULL;
			}
			ical_append_value(piline, pivalue);
			if (FALSE == ical_append_subval(pivalue, "YEARLY")) {
				return NULL;
			}
			pivalue = ical_new_value("BYDAY");
			if (NULL == pivalue) {
				return NULL;
			}
			ical_append_value(piline, pivalue);
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
			if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
				return NULL;
			}
			pivalue = ical_new_value("BYMONTH");
			if (NULL == pivalue) {
				return NULL;
			}
			ical_append_value(piline, pivalue);
			sprintf(tmp_buff, "%d", (int)ptzstruct->standarddate.month);
			if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
				return NULL;
			}
		} else if (1 == ptzstruct->standarddate.year) {
			piline = ical_new_line("RRULE");
			if (NULL == piline) {
				return NULL;
			}
			ical_append_line(pcomponent1, piline);
			pivalue = ical_new_value("FREQ");
			if (NULL == pivalue) {
				return NULL;
			}
			ical_append_value(piline, pivalue);
			if (FALSE == ical_append_subval(pivalue, "YEARLY")) {
				return NULL;
			}
			pivalue = ical_new_value("BYMONTHDAY");
			if (NULL == pivalue) {
				return NULL;
			}
			ical_append_value(piline, pivalue);
			sprintf(tmp_buff, "%d", (int)ptzstruct->standarddate.day);
			pivalue = ical_new_value("BYMONTH");
			if (NULL == pivalue) {
				return NULL;
			}
			ical_append_value(piline, pivalue);
			sprintf(tmp_buff, "%d", (int)ptzstruct->standarddate.month);
			if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
				return NULL;
			}
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
	ical_append_line(pcomponent1, piline);
	utc_offset = (-1)*(ptzstruct->bias + ptzstruct->standardbias);
	if (utc_offset >= 0) {
		tmp_buff[0] = '+';
	} else {
		tmp_buff[0] = '-';
	}
	utc_offset = abs(utc_offset);
	sprintf(tmp_buff + 1, "%02d%02d", utc_offset/60, utc_offset%60);
	piline = ical_new_simple_line("TZOFFSETTO", tmp_buff);
	ical_append_line(pcomponent1, piline);
	if (0 == ptzstruct->daylightdate.month) {
		return pcomponent;
	}
	/* DAYLIGHT component */
	pcomponent1 = ical_new_component("DAYLIGHT");
	if (NULL == pcomponent1) {
		return NULL;
	}
	ical_append_component(pcomponent, pcomponent1);
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
	ical_append_line(pcomponent1, piline);
	if (0 == ptzstruct->daylightdate.year) {
		piline = ical_new_line("RRULE");
		if (NULL == piline) {
			return NULL;
		}
		ical_append_line(pcomponent1, piline);
		pivalue = ical_new_value("FREQ");
		if (NULL == pivalue) {
			return NULL;
		}
		ical_append_value(piline, pivalue);
		if (FALSE == ical_append_subval(pivalue, "YEARLY")) {
			return NULL;
		}
		pivalue = ical_new_value("BYDAY");
		if (NULL == pivalue) {
			return NULL;
		}
		ical_append_value(piline, pivalue);
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
		if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
			return NULL;
		}
		pivalue = ical_new_value("BYMONTH");
		if (NULL == pivalue) {
			return NULL;
		}
		ical_append_value(piline, pivalue);
		sprintf(tmp_buff, "%d", (int)ptzstruct->daylightdate.month);
		if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
			return NULL;
		}
	} else if (1 == ptzstruct->daylightdate.year) {
		piline = ical_new_line("RRULE");
		if (NULL == piline) {
			return NULL;
		}
		ical_append_line(pcomponent1, piline);
		pivalue = ical_new_value("FREQ");
		if (NULL == pivalue) {
			return NULL;
		}
		ical_append_value(piline, pivalue);
		if (FALSE == ical_append_subval(pivalue, "YEARLY")) {
			return NULL;
		}
		pivalue = ical_new_value("BYMONTHDAY");
		if (NULL == pivalue) {
			return NULL;
		}
		ical_append_value(piline, pivalue);
		sprintf(tmp_buff, "%d", (int)ptzstruct->daylightdate.day);
		pivalue = ical_new_value("BYMONTH");
		if (NULL == pivalue) {
			return NULL;
		}
		ical_append_value(piline, pivalue);
		sprintf(tmp_buff, "%d", (int)ptzstruct->daylightdate.month);
		if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
			return NULL;
		}
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
	ical_append_line(pcomponent1, piline);
	utc_offset = (-1)*(ptzstruct->bias + ptzstruct->daylightbias);
	if (utc_offset >= 0) {
		tmp_buff[0] = '+';
	} else {
		tmp_buff[0] = '-';
	}
	utc_offset = abs(utc_offset);
	sprintf(tmp_buff + 1, "%02d%02d", utc_offset/60, utc_offset%60);
	piline = ical_new_simple_line("TZOFFSETTO", tmp_buff);
	ical_append_line(pcomponent1, piline);
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
			return entryid_to_username(pvalue, alloc, username);
		} else {
			if (0 == strcasecmp(pvalue, "SMTP")) {
				pvalue = tpropval_array_get_propval(
						prcpt, PROP_TAG_EMAILADDRESS);
			} else if (0 == strcasecmp(pvalue, "EX")) {
				pvalue = tpropval_array_get_propval(
						prcpt, PROP_TAG_EMAILADDRESS);
				if (NULL != pvalue) {
					if (TRUE == essdn_to_username(pvalue, username)) {
						return TRUE;
					}
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
	strncpy(username, pvalue, 128);
	return TRUE;
}

static BOOL oxcical_export_recipient_table(
	ICAL_COMPONENT *pevent_component,
	ENTRYID_TO_USERNAME entryid_to_username,
	ESSDN_TO_USERNAME essdn_to_username,
	EXT_BUFFER_ALLOC alloc, const char *partstat,
	MESSAGE_CONTENT *pmsg)
{
	int i;
	BOOL b_rsvp;
	void *pvalue;
	ICAL_LINE *piline;
	char username[128];
	char tmp_value[256];
	ICAL_PARAM *piparam;
	ICAL_VALUE *pivalue;
	
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
	if (0 == strcasecmp(pvalue, "IPM.Appointment")) {
		return TRUE;
	}
	if (0 == strcasecmp(pvalue, "IPM.Schedule.Meeting.Resp.Pos") ||
		0 == strcasecmp(pvalue, "IPM.Schedule.Meeting.Resp.Tent") ||
		0 == strcasecmp(pvalue, "IPM.Schedule.Meeting.Resp.Neg")) {
		pvalue = tpropval_array_get_propval(&pmsg->proplist,
					PROP_TAG_SENTREPRESENTINGSMTPADDRESS);
		if (NULL == pvalue) {
			return FALSE;
		}
		piline = ical_new_line("ATTENDEE");
		if (NULL == piline) {
			return FALSE;
		}
		ical_append_line(pevent_component, piline);
		piparam = ical_new_param("PARTSTAT");
		if (NULL == piparam) {
			return FALSE;
		}
		ical_append_param(piline, piparam);
		if (FALSE == ical_append_paramval(piparam, partstat)) {
			return FALSE;
		}
		sprintf(tmp_value, "MAILTO:%s", pvalue);
		pivalue = ical_new_value(NULL);
		if (NULL == pivalue) {
			return FALSE;
		}
		ical_append_value(piline, pivalue);
		return ical_append_subval(pivalue, tmp_value);
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
		ical_append_line(pevent_component, piline);
		piparam = ical_new_param("ROLE");
		if (NULL == piparam) {
			return FALSE;
		}
		ical_append_param(piline, piparam);
		if (NULL != pvalue && 0x00000002 == *(uint32_t*)pvalue) {
			if (FALSE == ical_append_paramval(piparam, "OPT-PARTICIPANT")) {
				return FALSE;
			}
		} else if (NULL != pvalue && 0x00000003 == *(uint32_t*)pvalue) {
			if (FALSE == ical_append_paramval(piparam, "NON-PARTICIPANT")) {
				return FALSE;
			}
		} else {
			if (FALSE == ical_append_paramval(piparam, "REQ-PARTICIPANT")) {
				return FALSE;
			}
		}
		if (NULL != partstat) {
			piparam = ical_new_param("PARTSTAT");
			if (NULL == piparam) {
				return FALSE;
			}
			ical_append_param(piline, piparam);
			if (FALSE == ical_append_paramval(piparam, partstat)) {
				return FALSE;
			}
		}
		if (TRUE == b_rsvp) {
			piparam = ical_new_param("RSVP");
			if (NULL == piparam) {
				return FALSE;
			}
			ical_append_param(piline, piparam);
			if (FALSE == ical_append_paramval(piparam, "TRUE")) {
				return FALSE;
			}
		}
		pvalue = tpropval_array_get_propval(
			pmsg->children.prcpts->pparray[i],
			PROP_TAG_DISPLAYNAME);
		if (NULL != pvalue) {
			piparam = ical_new_param("CN");
			if (NULL == piparam) {
				return FALSE;
			}
			ical_append_param(piline, piparam);
			if (FALSE == ical_append_paramval(piparam, pvalue)) {
				return FALSE;
			}
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
		ical_append_value(piline, pivalue);
		if (FALSE == ical_append_subval(pivalue, tmp_value)) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL oxcical_export_rrule(ICAL_COMPONENT *ptz_component,
	ICAL_COMPONENT *pcomponent, APPOINTMENTRECURRENCEPATTERN *papprecurr)
{
	ICAL_TIME itime;
	time_t unix_time;
	uint64_t nt_time;
	ICAL_LINE *piline;
	const char *str_tag;
	ICAL_VALUE *pivalue;
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
	piline = ical_new_line(str_tag);
	if (NULL == piline) {
		return FALSE;
	}
	ical_append_line(pcomponent, piline);
	switch (papprecurr->recurrencepattern.patterntype) {
	case PATTERNTYPE_DAY:
		pivalue = ical_new_value("FREQ");
		if (NULL == pivalue) {
			return FALSE;
		}
		ical_append_value(piline, pivalue);
		if (FALSE == ical_append_subval(pivalue, "DAILY")) {
			return FALSE;
		}
		sprintf(tmp_buff, "%u",
			papprecurr->recurrencepattern.period/1440);
		pivalue = ical_new_value("INTERVAL");
		if (NULL == pivalue) {
			return FALSE;
		}
		ical_append_value(piline, pivalue);
		if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
			return FALSE;
		}
		break;
	case PATTERNTYPE_WEEK:
		pivalue = ical_new_value("FREQ");
		if (NULL == pivalue) {
			return FALSE;
		}
		ical_append_value(piline, pivalue);
		if (FALSE == ical_append_subval(pivalue, "WEEKLY")) {
			return FALSE;
		}
		sprintf(tmp_buff, "%u",
			papprecurr->recurrencepattern.period);
		pivalue = ical_new_value("INTERVAL");
		if (NULL == pivalue) {
			return FALSE;
		}
		ical_append_value(piline, pivalue);
		if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
			return FALSE;
		}
		pivalue = ical_new_value("BYDAY");
		if (NULL == pivalue) {
			return FALSE;
		}
		ical_append_value(piline, pivalue);
		if (WEEKRECURRENCEPATTERN_SU&
			papprecurr->recurrencepattern.
			patterntypespecific.weekrecurrence) {
			if (FALSE == ical_append_subval(pivalue, "SU")) {
				return FALSE;
			}
		}
		if (WEEKRECURRENCEPATTERN_M&
			papprecurr->recurrencepattern.
			patterntypespecific.weekrecurrence) {
			if (FALSE == ical_append_subval(pivalue, "MO")) {
				return FALSE;
			}
		}
		if (WEEKRECURRENCEPATTERN_TU&
			papprecurr->recurrencepattern.
			patterntypespecific.weekrecurrence) {
			if (FALSE == ical_append_subval(pivalue, "TU")) {
				return FALSE;
			}
		}
		if (WEEKRECURRENCEPATTERN_W&
			papprecurr->recurrencepattern.
			patterntypespecific.weekrecurrence) {
			if (FALSE == ical_append_subval(pivalue, "WE")) {
				return FALSE;
			}
		}
		if (WEEKRECURRENCEPATTERN_TH&
			papprecurr->recurrencepattern.
			patterntypespecific.weekrecurrence) {
			if (FALSE == ical_append_subval(pivalue, "TH")) {
				return FALSE;
			}
		}
		if (WEEKRECURRENCEPATTERN_F&
			papprecurr->recurrencepattern.
			patterntypespecific.weekrecurrence) {
			if (FALSE == ical_append_subval(pivalue, "FR")) {
				return FALSE;
			}
		}
		if (WEEKRECURRENCEPATTERN_SA&
			papprecurr->recurrencepattern.
			patterntypespecific.weekrecurrence) {
			if (FALSE == ical_append_subval(pivalue, "SA")) {
				return FALSE;
			}
		}
		break;
	case PATTERNTYPE_MONTH:
	case PATTERNTYPE_HJMONTH:
		pivalue = ical_new_value("FREQ");
		if (NULL == pivalue) {
			return FALSE;
		}
		ical_append_value(piline, pivalue);
		if (0 != papprecurr->recurrencepattern.period%12) {
			if (FALSE == ical_append_subval(pivalue, "MONTHLY")) {
				return FALSE;
			}
			sprintf(tmp_buff, "%u",
				papprecurr->recurrencepattern.period);
			pivalue = ical_new_value("INTERVAL");
			if (NULL == pivalue) {
				return FALSE;
			}
			ical_append_value(piline, pivalue);
			if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
				return FALSE;
			}
			pivalue = ical_new_value("BYMONTHDAY");
			if (NULL == pivalue) {
				return FALSE;
			}
			ical_append_value(piline, pivalue);
			if (31 == papprecurr->recurrencepattern.
				patterntypespecific.dayofmonth) {
				strcpy(tmp_buff, "-1");
			} else {
				sprintf(tmp_buff, "%u",
					papprecurr->recurrencepattern.
					patterntypespecific.dayofmonth);
			}
			if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
				return FALSE;
			}
		} else {
			if (FALSE == ical_append_subval(pivalue, "YEARLY")) {
				return FALSE;
			}
			sprintf(tmp_buff, "%u",
				papprecurr->recurrencepattern.period/12);
			pivalue = ical_new_value("INTERVAL");
			if (NULL == pivalue) {
				return FALSE;
			}
			ical_append_value(piline, pivalue);
			if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
				return FALSE;
			}
			pivalue = ical_new_value("BYMONTHDAY");
			if (NULL == pivalue) {
				return FALSE;
			}
			ical_append_value(piline, pivalue);
			if (31 == papprecurr->recurrencepattern.
				patterntypespecific.dayofmonth) {
				strcpy(tmp_buff, "-1");
			} else {
				sprintf(tmp_buff, "%u",
					papprecurr->recurrencepattern.
					patterntypespecific.dayofmonth);
			}
			if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
				return FALSE;
			}
			pivalue = ical_new_value("BYMONTH");
			if (NULL == pivalue) {
				return FALSE;
			}
			ical_append_value(piline, pivalue);
			ical_get_itime_from_yearday(1601, 
				papprecurr->recurrencepattern.firstdatetime/
				1440 + 1, &itime);
			sprintf(tmp_buff, "%u", itime.month);
			if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
				return FALSE;
			}
		}
		break;
	case PATTERNTYPE_MONTHNTH:
	case PATTERNTYPE_HJMONTHNTH:
		pivalue = ical_new_value("FREQ");
		if (NULL == pivalue) {
			return FALSE;
		}
		ical_append_value(piline, pivalue);
		if (0 != papprecurr->recurrencepattern.period%12) {
			if (FALSE == ical_append_subval(pivalue, "MONTHLY")) {
				return FALSE;
			}
			sprintf(tmp_buff, "%u",
				papprecurr->recurrencepattern.period);
			pivalue = ical_new_value("INTERVAL");
			if (NULL == pivalue) {
				return FALSE;
			}
			ical_append_value(piline, pivalue);
			if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
				return FALSE;
			}
			pivalue = ical_new_value("BYDAY");
			if (NULL == pivalue) {
				return FALSE;
			}
			ical_append_value(piline, pivalue);
			if (WEEKRECURRENCEPATTERN_SU&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (FALSE == ical_append_subval(pivalue, "SU")) {
					return FALSE;
				}
			}
			if (WEEKRECURRENCEPATTERN_M&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (FALSE == ical_append_subval(pivalue, "MO")) {
					return FALSE;
				}
			}
			if (WEEKRECURRENCEPATTERN_TU&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (FALSE == ical_append_subval(pivalue, "TU")) {
					return FALSE;
				}
			}
			if (WEEKRECURRENCEPATTERN_W&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (FALSE == ical_append_subval(pivalue, "WE")) {
					return FALSE;
				}
			}
			if (WEEKRECURRENCEPATTERN_TH&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (FALSE == ical_append_subval(pivalue, "TH")) {
					return FALSE;
				}
			}
			if (WEEKRECURRENCEPATTERN_F&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (FALSE == ical_append_subval(pivalue, "FR")) {
					return FALSE;
				}
			}
			if (WEEKRECURRENCEPATTERN_SA&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (FALSE == ical_append_subval(pivalue, "SA")) {
					return FALSE;
				}
			}
			pivalue = ical_new_value("BYSETPOS");
			if (NULL == pivalue) {
				return FALSE;
			}
			ical_append_value(piline, pivalue);
			if (5 == papprecurr->recurrencepattern.
				patterntypespecific.monthnth.recurrencenum) {
				strcpy(tmp_buff, "-1");
			} else {
				sprintf(tmp_buff, "%u",
					papprecurr->recurrencepattern.
					patterntypespecific.monthnth.recurrencenum);
			}
			if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
				return FALSE;
			}
		} else {
			if (FALSE == ical_append_subval(pivalue, "YEARLY")) {
				return FALSE;
			}
			sprintf(tmp_buff, "%u",
				papprecurr->recurrencepattern.period/12);
			pivalue = ical_new_value("INTERVAL");
			if (NULL == pivalue) {
				return FALSE;
			}
			ical_append_value(piline, pivalue);
			if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
				return FALSE;
			}
			pivalue = ical_new_value("BYDAY");
			if (NULL == pivalue) {
				return FALSE;
			}
			ical_append_value(piline, pivalue);
			if (WEEKRECURRENCEPATTERN_SU&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (FALSE == ical_append_subval(pivalue, "SU")) {
					return FALSE;
				}
			}
			if (WEEKRECURRENCEPATTERN_M&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (FALSE == ical_append_subval(pivalue, "MO")) {
					return FALSE;
				}
			}
			if (WEEKRECURRENCEPATTERN_TU&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (FALSE == ical_append_subval(pivalue, "TU")) {
					return FALSE;
				}
			}
			if (WEEKRECURRENCEPATTERN_W&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (FALSE == ical_append_subval(pivalue, "WE")) {
					return FALSE;
				}
			}
			if (WEEKRECURRENCEPATTERN_TH&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (FALSE == ical_append_subval(pivalue, "TH")) {
					return FALSE;
				}
			}
			if (WEEKRECURRENCEPATTERN_F&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (FALSE == ical_append_subval(pivalue, "FR")) {
					return FALSE;
				}
			}
			if (WEEKRECURRENCEPATTERN_SA&papprecurr->recurrencepattern.
				patterntypespecific.monthnth.weekrecurrence) {
				if (FALSE == ical_append_subval(pivalue, "SA")) {
					return FALSE;
				}
			}
			pivalue = ical_new_value("BYSETPOS");
			if (NULL == pivalue) {
				return FALSE;
			}
			ical_append_value(piline, pivalue);
			if (5 == papprecurr->recurrencepattern.
				patterntypespecific.monthnth.recurrencenum) {
				strcpy(tmp_buff, "-1");
			} else {
				sprintf(tmp_buff, "%u",
					papprecurr->recurrencepattern.
					patterntypespecific.monthnth.recurrencenum);
			}
			if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
				return FALSE;
			}
			pivalue = ical_new_value("BYMONTH");
			if (NULL == pivalue) {
				return FALSE;
			}
			ical_append_value(piline, pivalue);
			sprintf(tmp_buff, "%u",
				papprecurr->recurrencepattern.firstdatetime);
			if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
				return FALSE;
			}
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
		ical_append_value(piline, pivalue);
		if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
			return FALSE;
		}
	} else if (ENDTYPE_AFTER_DATE ==
		papprecurr->recurrencepattern.endtype) {
		nt_time = papprecurr->recurrencepattern.enddate
						+ papprecurr->starttimeoffset;
		nt_time *= 600000000;
		unix_time = rop_util_nttime_to_unix(nt_time);
		ical_utc_to_datetime(NULL, unix_time, &itime);
		if (FALSE == ical_itime_to_utc(
			ptz_component, itime, &unix_time)) {
			return FALSE;
		}
		ical_utc_to_datetime(NULL, unix_time, &itime);
		sprintf(tmp_buff, "%04d%02d%02dT%02d%02d%02dZ",
			itime.year, itime.month, itime.day,
			itime.hour, itime.minute, itime.second);
		pivalue = ical_new_value("UNTIL");
		if (NULL == pivalue) {
			return FALSE;
		}
		ical_append_value(piline, pivalue);
		if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
			return FALSE;
		}
	}
	if (PATTERNTYPE_WEEK == papprecurr->recurrencepattern.patterntype) {
		pivalue = ical_new_value("WKST");
		if (NULL == pivalue) {
			return FALSE;
		}
		ical_append_value(piline, pivalue);
		switch (papprecurr->recurrencepattern.firstdow) {
		case 0:
			if (FALSE == ical_append_subval(pivalue, "SU")) {
				return FALSE;
			}
			break;
		case 1:
			if (FALSE == ical_append_subval(pivalue, "MO")) {
				return FALSE;
			}
			break;
		case 2:
			if (FALSE == ical_append_subval(pivalue, "TU")) {
				return FALSE;
			}
			break;
		case 3:
			if (FALSE == ical_append_subval(pivalue, "WE")) {
				return FALSE;
			}
			break;
		case 4:
			if (FALSE == ical_append_subval(pivalue, "TH")) {
				return FALSE;
			}
			break;
		case 5:
			if (FALSE == ical_append_subval(pivalue, "FR")) {
				return FALSE;
			}
			break;
		case 6:
			if (FALSE == ical_append_subval(pivalue, "SA")) {
				return FALSE;
			}
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

static BOOL oxcical_export_exdate(const char *tzid,
	BOOL b_date, ICAL_COMPONENT *pcomponent,
	APPOINTMENTRECURRENCEPATTERN *papprecurr)
{
	int i, j;
	BOOL b_found;
	time_t tmp_time;
	ICAL_TIME itime;
	ICAL_LINE *piline;
	uint64_t tmp_int64;
	ICAL_VALUE *pivalue;
	ICAL_PARAM *piparam;
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
	ical_append_line(pcomponent, piline);
	pivalue = ical_new_value(NULL);
	if (NULL == pivalue) {
		return FALSE;
	}
	ical_append_value(piline, pivalue);
	if (TRUE == b_date) {
		piparam = ical_new_param("VALUE");
		if (NULL == piparam) {
			return FALSE;
		}
		ical_append_param(piline, piparam);
		if (FALSE == ical_append_paramval(piparam, "DATE")) {
			return FALSE;
		}
	} else {
		if (NULL != tzid) {
			piparam = ical_new_param("TZID");
			if (NULL == piparam) {
				return FALSE;
			}
			ical_append_param(piline, piparam);
			if (FALSE == ical_append_paramval(piparam, tzid)) {
				return FALSE;
			}
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
		if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
			return FALSE;
		}
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

static BOOL oxcical_export_rdate(const char *tzid,
	BOOL b_date, ICAL_COMPONENT *pcomponent,
	APPOINTMENTRECURRENCEPATTERN *papprecurr)
{
	int i, j;
	BOOL b_found;
	time_t tmp_time;
	ICAL_TIME itime;
	ICAL_LINE *piline;
	uint64_t tmp_int64;
	ICAL_VALUE *pivalue;
	ICAL_PARAM *piparam;
	char tmp_buff[1024];
	
	piline = ical_new_line("RDATE");
	if (NULL == piline) {
		return FALSE;
	}
	ical_append_line(pcomponent, piline);
	pivalue = ical_new_value(NULL);
	if (NULL == pivalue) {
		return FALSE;
	}
	ical_append_value(piline, pivalue);
	if (TRUE == b_date) {
		piparam = ical_new_param("VALUE");
		if (NULL == piparam) {
			return FALSE;
		}
		ical_append_param(piline, piparam);
		if (FALSE == ical_append_paramval(piparam, "DATE")) {
			return FALSE;
		}
	} else {
		if (NULL != tzid) {
			piparam = ical_new_param("TZID");
			if (NULL == piparam) {
				return FALSE;
			}
			ical_append_param(piline, piparam);
			if (FALSE == ical_append_paramval(piparam, tzid)) {
				return FALSE;
			}
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
		if (FALSE == ical_append_subval(pivalue, tmp_buff)) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL oxcical_export_internal(const char *method,
	const char *tzid, ICAL_COMPONENT *ptz_component,
	MESSAGE_CONTENT *pmsg, ICAL *pical,
	ENTRYID_TO_USERNAME entryid_to_username,
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
	ICAL_LINE *piline;
	EXT_PULL ext_pull;
	EXT_PUSH ext_push;
	BOOL b_recurrence;
	time_t start_time;
	BOOL b_exceptional;
	ICAL_VALUE *pivalue;
	ICAL_PARAM *piparam;
	uint32_t *psequence;
	char tmp_buff[1024];
	char tmp_buff1[2048];
	uint32_t proptag_xrt;
	PROPID_ARRAY propids;
	const char *partstat;
	const char *str_value;
	const char *planguage;
	uint32_t *pbusystatus;
	PROPERTY_NAME propname;
	PROPNAME_ARRAY propnames;
	TIMEZONESTRUCT tz_struct;
	MESSAGE_CONTENT *pembedded;
	ICAL_COMPONENT *pcomponent;
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
		if (0 == strcasecmp(pvalue, "IPM.Appointment")) {
			method = "PUBLISH";
		} else if (0 == strcasecmp(pvalue, "IPM.Schedule.Meeting.Request")) {
			method = "REQUEST";
			partstat = "NEEDS-ACTION";
		} else if (0 == strcasecmp(pvalue, "IPM.Schedule.Meeting.Resp.Pos")) {
			method = "REPLY";
			partstat = "ACCEPTED";
		} else if (0 == strcasecmp(pvalue, "IPM.Schedule.Meeting.Resp.Tent")) {
			partstat = "TENTATIVE";
			propname.kind = KIND_LID;
			propname.plid = &lid;
			rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
			/* PidLidAppointmentCounterProposal */
			lid = 0x00008257;
			if (FALSE == get_propids(&propnames, &propids)) {
				return FALSE;
			}
			proptag = ((uint32_t)propids.ppropid[0]) << 16 |
										PROPVAL_TYPE_BYTE;
			pvalue = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
			if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
				b_proposal = TRUE;
				method = "COUNTER";
			} else {
				method = "REPLY";
			}
		} else if (0 == strcasecmp(pvalue, "IPM.Schedule.Meeting.Resp.Neg")) {
			method = "REPLY";
			partstat = "DECLINED";
		} else if (0 == strcasecmp(pvalue, "IPM.Schedule.Meeting.Canceled")) {
			method = "CANCEL";
			partstat = "NEEDS-ACTION";
		} else {
			return FALSE;
		}
	}
	propname.kind = KIND_LID;
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
	proptag = ((uint32_t)propids.ppropid[0]) << 16 |
							PROPVAL_TYPE_FILETIME;
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, proptag);
	if (NULL == pvalue) {
		return FALSE;
	}
	start_time = rop_util_nttime_to_unix(*(uint64_t*)pvalue);
	
	propname.kind = KIND_LID;
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
	proptag = ((uint32_t)propids.ppropid[0]) << 16 |
							PROPVAL_TYPE_FILETIME;
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
		proptag = ((uint32_t)propids.ppropid[0]) << 16 |
									PROPVAL_TYPE_LONG;
		pvalue = tpropval_array_get_propval(
			&pmsg->proplist, proptag);
		if (NULL == pvalue) {
			end_time = start_time;
		} else {
			end_time = start_time + *(uint32_t*)pvalue;
		}
	}
	
	if (TRUE == b_exceptional) {
		goto EXPORT_VEVENT;
	}
	
	piline = ical_new_simple_line("METHOD", method);
	if (NULL == piline) {
		return FALSE;
	}
	ical_append_line(pical, piline);
	
	piline = ical_new_simple_line("PRODID",
		"-//Gridware Information//GRID 1.0 calendar//EN");
	if (NULL == piline) {
		return FALSE;
	}
	ical_append_line(pical, piline);
	
	piline = ical_new_simple_line("VERSION", "2.0");
	if (NULL == piline) {
		return FALSE;
	}
	ical_append_line(pical, piline);
	
	propname.kind = KIND_LID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	/* PidLidAppointmentRecur */
	lid = 0x00008216;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = ((uint32_t)propids.ppropid[0]) << 16 |
								PROPVAL_TYPE_BINARY;
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
			ical_append_line((ICAL*)pical, piline);
		}
	}
	
	make_gmtm(start_time, &tmp_tm);
	year = tmp_tm.tm_year + 1900;
	
	tzid = NULL;
	ptz_component = NULL;
	if (TRUE == b_recurrence) {
		propname.kind = KIND_LID;
		propname.plid = &lid;
		rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
		/* PidLidTimeZoneStruct */
		lid = 0x00008233;
		if (FALSE == get_propids(&propnames, &propids)) {
			return FALSE;
		}
		proptag = ((uint32_t)propids.ppropid[0]) << 16 |
									PROPVAL_TYPE_BINARY;
		pvalue = tpropval_array_get_propval(
			&pmsg->proplist, proptag);
		if (NULL != pvalue) {
			propname.kind = KIND_LID;
			propname.plid = &lid;
			rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
			/* PidLidTimeZoneDescription */
			lid = 0x00008234;
			if (FALSE == get_propids(&propnames, &propids)) {
				return FALSE;
			}
			proptag = ((uint32_t)propids.ppropid[0]) << 16 |
										PROPVAL_TYPE_WSTRING;
			tzid = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
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
			propname.kind = KIND_LID;
			propname.plid = &lid;
			rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
			/* PidLidAppointmentTimeZoneDefinitionRecur */
			lid = 0x00008260;
			if (FALSE == get_propids(&propnames, &propids)) {
				return FALSE;
			}
			proptag = ((uint32_t)propids.ppropid[0]) << 16 |
										PROPVAL_TYPE_BINARY;
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
		propname.kind = KIND_LID;
		propname.plid = &lid;
		rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
		/* PidLidAppointmentTimeZoneDefinitionStartDisplay */
		lid = 0x0000825E;
		if (FALSE == get_propids(&propnames, &propids)) {
			return FALSE;
		}
		proptag = ((uint32_t)propids.ppropid[0]) << 16 |
									PROPVAL_TYPE_BINARY;
		pvalue = tpropval_array_get_propval(
			&pmsg->proplist, proptag);
		if (NULL != pvalue) {
			/* PidLidAppointmentTimeZoneDefinitionEndDisplay */
			lid = 0x0000825F;
			if (FALSE == get_propids(&propnames, &propids)) {
				return FALSE;
			}
			proptag = ((uint32_t)propids.ppropid[0]) << 16 |
										PROPVAL_TYPE_BINARY;
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
	propname.kind = KIND_LID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	/* PidLidAppointmentSubType */
	lid = 0x00008215;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = ((uint32_t)propids.ppropid[0]) << 16 |
								PROPVAL_TYPE_BYTE;
	pvalue = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		b_allday = TRUE;
	} else {
		b_allday = FALSE;
	}

	pcomponent = ical_new_component("VEVENT");
	if (NULL == pcomponent) {
		return FALSE;
	}
	ical_append_component(pical, pcomponent);
	
	if (0 == strcmp(method, "REQUEST") ||
		0 == strcmp(method, "CANCEL")) {
		pvalue = tpropval_array_get_propval(&pmsg->proplist,
					PROP_TAG_SENTREPRESENTINGSMTPADDRESS);
		if (NULL != pvalue) {
			pvalue = tpropval_array_get_propval(&pmsg->proplist,
						PROP_TAG_SENTREPRESENTINGADDRESSTYPE);
			if (NULL != pvalue)
				if (0 == strcasecmp(pvalue, "SMTP")) {
					pvalue = tpropval_array_get_propval(&pmsg->proplist,
								PROP_TAG_SENTREPRESENTINGEMAILADDRESS);
				} else if (0 == strcasecmp(pvalue, "EX")) {
					pvalue = tpropval_array_get_propval(&pmsg->proplist,
								PROP_TAG_SENTREPRESENTINGEMAILADDRESS);
					if (NULL != pvalue) {
						if (FALSE == essdn_to_username(pvalue, tmp_buff)) {
							pvalue = NULL;
						} else {
							pvalue = tmp_buff;
						}
				} else {
					pvalue = NULL;
				}
			}
		}
		if (NULL != pvalue) {
			sprintf(tmp_buff1, "MAILTO:%s", pvalue);
			piline = ical_new_simple_line("ORGANIZER", tmp_buff1);
			if (NULL == piline) {
				return FALSE;
			}
			ical_append_line(pcomponent, piline);
			pvalue = tpropval_array_get_propval(&pmsg->proplist,
							PROP_TAG_SENTREPRESENTINGNAME);
			if (NULL != pvalue) {
				piparam = ical_new_param("CN");
				if (NULL == piparam) {
					return FALSE;
				}
				ical_append_param(piline, piparam);
				if (FALSE == ical_append_paramval(piparam, pvalue)) {
					return FALSE;
				}
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
			piline = ical_new_simple_line("COMMENT", pvalue);
		} else {
			piline = ical_new_simple_line("DESCRIPTION", pvalue);
		}
		if (NULL == piline) {
			return FALSE;
		}
		ical_append_line(pcomponent, piline);
		if (NULL != planguage) {
			piparam = ical_new_param("LANGUAGE");
			if (NULL == piparam) {
				return FALSE;
			}
			ical_append_param(piline, piparam);
			if (FALSE == ical_append_paramval(piparam, planguage)) {
				return FALSE;
			}
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
	
	propname.kind = KIND_LID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_MEETING, &propname.guid);
	/* PidLidGlobalObjectId */
	lid = 0x00000003;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = ((uint32_t)propids.ppropid[0]) << 16 |
								PROPVAL_TYPE_BINARY;
	pvalue = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
	if (NULL != pvalue) {
		ext_buffer_pull_init(&ext_pull, ((BINARY*)pvalue)->pb,
							((BINARY*)pvalue)->cb, alloc, 0);
		if (EXT_ERR_SUCCESS != ext_buffer_pull_globalobjectid(
			&ext_pull, &globalobjectid)) {
			return FALSE;
		}
		if (NULL != globalobjectid.data.pb &&
			0 == memcmp(globalobjectid.data.pb,
			"\x76\x43\x61\x6c\x2d\x55\x69\x64\x01\x00\x00\x00", 12)) {
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
			upper_string(tmp_buff1);
			piline = ical_new_simple_line("UID", tmp_buff1);
		}
		if (NULL == piline) {
			return FALSE;
		}
		ical_append_line(pcomponent, piline);
	} else {
		time(&cur_time);
		memset(&globalobjectid, 0, sizeof(GLOBALOBJECTID));
		memcpy(globalobjectid.arrayid,
			"\x04\x00\x00\x00\x82\x00\xE0\x00"
			"\x74\xC5\xB7\x10\x1A\x82\xE0\x08", 16);
		globalobjectid.creationtime = rop_util_unix_to_nttime(cur_time);
		globalobjectid.data.cb = 16;
		globalobjectid.data.pb = tmp_buff1;
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
		upper_string(tmp_buff1);
		piline = ical_new_simple_line("UID", tmp_buff1);
		if (NULL == piline) {
			return FALSE;
		}
		ical_append_line(pcomponent, piline);
	}
	
	propname.kind = KIND_LID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	/* PidLidExceptionReplaceTime */
	lid = 0x00008228;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag_xrt = ((uint32_t)propids.ppropid[0]) << 16 |
								PROPVAL_TYPE_FILETIME;
	
	pvalue = tpropval_array_get_propval(
			&pmsg->proplist, proptag_xrt);
	if (NULL == pvalue) {
		propname.kind = KIND_LID;
		propname.plid = &lid;
		rop_util_get_common_pset(PSETID_MEETING, &propname.guid);
		/* PidLidIsException */
		lid = 0x0000000A;
		if (FALSE == get_propids(&propnames, &propids)) {
			return FALSE;
		}
		proptag = ((uint32_t)propids.ppropid[0]) << 16 |
									PROPVAL_TYPE_BYTE;
		pvalue = tpropval_array_get_propval(
					&pmsg->proplist, proptag);
		if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
			propname.kind = KIND_LID;
			propname.plid = &lid;
			rop_util_get_common_pset(PSETID_MEETING, &propname.guid);
			/* PidLidStartRecurrenceTime */
			lid = 0x0000000E;
			if (FALSE == get_propids(&propnames, &propids)) {
				return FALSE;
			}
			proptag = ((uint32_t)propids.ppropid[0]) << 16 |
											PROPVAL_TYPE_LONG;
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
				proptag = ((uint32_t)propids.ppropid[0]) << 16 |
											PROPVAL_TYPE_BINARY;
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
			ical_append_line(pcomponent, piline);
			if (NULL != ptz_component) {
				piparam = ical_new_param("TZID");
				if (NULL == piparam) {
					return FALSE;
				}
				ical_append_param(piline, piparam);
				if (FALSE == ical_append_paramval(piparam, tzid)) {
					return FALSE;
				}
			}
		} else {
			sprintf(tmp_buff, "%04d%02d%02d",
				itime.year, itime.month, itime.day);
			piline = ical_new_simple_line("RECURRENCE-ID", tmp_buff);
			if (NULL == piline) {
				return FALSE;
			}
			ical_append_line(pcomponent, piline);
		}
	} else {
		if (TRUE == b_exceptional) {
			return FALSE;
		}
	}
	
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_SUBJECT);
	if (NULL != pvalue) {
		piline = ical_new_simple_line("SUMMARY", pvalue);
		if (NULL == piline) {
			return FALSE;
		}
		ical_append_line(pcomponent, piline);
		if (NULL != planguage) {
			piparam = ical_new_param("LANGUAGE");
			if (NULL == piparam) {
				return FALSE;
			}
			ical_append_param(piline, piparam);
			if (FALSE == ical_append_paramval(piparam, planguage)) {
				return FALSE;
			}
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
	ical_append_line(pcomponent, piline);
	if (NULL == ptz_component && TRUE == b_allday) {
		piparam = ical_new_param("VALUE");
		if (NULL == piparam) {
			return FALSE;
		}
		ical_append_param(piline, piparam);
		if (FALSE == ical_append_paramval(piparam, "DATE")) {
			return FALSE;
		}
	}
	if (NULL != ptz_component) {
		piparam = ical_new_param("TZID");
		if (NULL == piparam) {
			return FALSE;
		}
		ical_append_param(piline, piparam);
		if (FALSE == ical_append_paramval(piparam, tzid)) {
			return FALSE;
		}
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
		ical_append_line(pcomponent, piline);
		if (NULL == ptz_component && TRUE == b_allday) {
			piparam = ical_new_param("VALUE");
			if (NULL == piparam) {
				return FALSE;
			}
			ical_append_param(piline, piparam);
			if (FALSE == ical_append_paramval(piparam, "DATE")) {
				return FALSE;
			}
		}
		if (NULL != ptz_component) {
			piparam = ical_new_param("TZID");
			if (NULL == piparam) {
				return FALSE;
			}
			ical_append_param(piline, piparam);
			if (FALSE == ical_append_paramval(piparam, tzid)) {
				return FALSE;
			}
		}
	}
	
	/* PidNameKeywords */
	propname.kind = KIND_NAME;
	propname.pname = "Keywords";
	rop_util_get_common_pset(PS_PUBLIC_STRINGS, &propname.guid);
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = ((uint32_t)propids.ppropid[0]) << 16 |
						PROPVAL_TYPE_WSTRING_ARRAY;
	pvalue = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
	if (NULL != pvalue) {
		piline = ical_new_line("CATEGORIS");
		if (NULL == piline) {
			return FALSE;
		}
		ical_append_line(pical, piline);
		pivalue = ical_new_value(NULL);
		if (NULL == pivalue) {
			return FALSE;
		}
		ical_append_value(piline, pivalue);
		for (i=0; i<((STRING_ARRAY*)pvalue)->count; i++) {
			if (FALSE == ical_append_subval(pivalue,
				((STRING_ARRAY*)pvalue)->ppstr[i])) {
				return FALSE;
			}
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
	ical_append_line(pcomponent, piline);
	
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
		ical_append_line(pcomponent, piline);
	}
	
	propname.kind = KIND_LID;
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
	proptag = ((uint32_t)propids.ppropid[0]) << 16 |
								PROPVAL_TYPE_FILETIME;
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
		ical_append_line(pcomponent, piline);
	}
	
	propname.kind = KIND_LID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	/* PidLidBusyStatus */
	lid = 0x00008205;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = ((uint32_t)propids.ppropid[0]) << 16 |
								PROPVAL_TYPE_LONG;
	pbusystatus = tpropval_array_get_propval(
					&pmsg->proplist, proptag);
	if (NULL != pbusystatus) {
		switch (*pbusystatus) {
		case 0:
		case 4:
			piline = ical_new_simple_line("TRANSP", "TRANSPARENT");
			if (NULL == piline) {
				return FALSE;
			}
			ical_append_line(pcomponent, piline);
			break;
		case 1:
		case 2:
		case 3:
			piline = ical_new_simple_line("TRANSP", "OPAQUE");
			if (NULL == piline) {
				return FALSE;
			}
			ical_append_line(pcomponent, piline);
			break;
		}
	}
	
	propname.kind = KIND_LID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	/* PidLidAppointmentSequence */
	lid = 0x00008201;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = ((uint32_t)propids.ppropid[0]) << 16 |
								PROPVAL_TYPE_LONG;
	psequence = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
	if (NULL != psequence) {
		sprintf(tmp_buff, "%u", *psequence);
		piline = ical_new_simple_line("SEQUENCE", tmp_buff);
		if (NULL == piline) {
			return FALSE;
		}
		ical_append_line(pcomponent, piline);
	}
	
	propname.kind = KIND_LID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	/* PidLidLocation */
	lid = 0x00008208;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = ((uint32_t)propids.ppropid[0]) << 16 |
								PROPVAL_TYPE_WSTRING;
	pvalue = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
	if (NULL != pvalue) {
		piline = ical_new_simple_line("LOCATION", pvalue);
		if (NULL == piline) {
			return FALSE;
		}
		ical_append_line(pcomponent, piline);
		propname.kind = KIND_NAME;
		rop_util_get_common_pset(PS_PUBLIC_STRINGS, &propname.guid);
		/* PidNameLocationUrl */
		propname.pname = "urn:schemas:calendar:locationurl";
		if (FALSE == get_propids(&propnames, &propids)) {
			return FALSE;
		}
		proptag = ((uint32_t)propids.ppropid[0]) << 16 |
									PROPVAL_TYPE_WSTRING;
		pvalue = tpropval_array_get_propval(
					&pmsg->proplist, proptag);
		if (NULL != pvalue) {
			piparam = ical_new_param("ALTREP");
			if (NULL == piparam) {
				return FALSE;
			}
			ical_append_param(piline, piparam);
			if (FALSE == ical_append_paramval(piparam, pvalue)) {
				return FALSE;
			}
		}
		if (NULL != planguage) {
			piparam = ical_new_param("LANGUAGE");
			if (NULL == piparam) {
				return FALSE;
			}
			ical_append_param(piline, piparam);
			if (FALSE == ical_append_paramval(piparam, planguage)) {
				return FALSE;
			}
		}
	}
	
	if (NULL != psequence) {
		sprintf(tmp_buff, "%u", *psequence);
		piline = ical_new_simple_line(
			"X-MICROSOFT-CDO-APPT-SEQUENCE", tmp_buff);
		if (NULL == piline) {
			return FALSE;
		}
		ical_append_line(pcomponent, piline);
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
		ical_append_line(pcomponent, piline);
	}
	
	if (NULL != pbusystatus) {
		switch (*pbusystatus) {
		case 0:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-BUSYSTATUS", "FREE");
			if (NULL == piline) {
				return FALSE;
			}
			ical_append_line(pcomponent, piline);
			break;
		case 1:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-BUSYSTATUS", "TENTATIVE");
			if (NULL == piline) {
				return FALSE;
			}
			ical_append_line(pcomponent, piline);
			break;
		case 2:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-BUSYSTATUS", "BUSY");
			if (NULL == piline) {
				return FALSE;
			}
			ical_append_line(pcomponent, piline);
			break;
		case 3:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-BUSYSTATUS", "OOF");
			if (NULL == piline) {
				return FALSE;
			}
			ical_append_line(pcomponent, piline);
			break;
		}
	}
	
	propname.kind = KIND_LID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	/* PidLidIntendedBusyStatus */
	lid = 0x00008224;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = ((uint32_t)propids.ppropid[0]) << 16 |
								PROPVAL_TYPE_LONG;
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
			ical_append_line(pcomponent, piline);
			break;
		case 1:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-INTENDEDSTATUS", "TENTATIVE");
			if (NULL == piline) {
				return FALSE;
			}
			ical_append_line(pcomponent, piline);
			break;
		case 2:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-INTENDEDSTATUS", "BUSY");
			if (NULL == piline) {
				return FALSE;
			}
			ical_append_line(pcomponent, piline);
			break;
		case 3:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-INTENDEDSTATUS", "OOF");
			if (NULL == piline) {
				return FALSE;
			}
			ical_append_line(pcomponent, piline);
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
	ical_append_line(pcomponent, piline);
	
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
			ical_append_line(pcomponent, piline);
			break;
		case 1:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-IMPORTANCE", "1");
			if (NULL == piline) {
				return FALSE;
			}
			ical_append_line(pcomponent, piline);
			break;
		case 2:
			piline = ical_new_simple_line(
				"X-MICROSOFT-CDO-IMPORTANCE", "2");
			if (NULL == piline) {
				return FALSE;
			}
			ical_append_line(pcomponent, piline);
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
	ical_append_line(pcomponent, piline);
	
	propname.kind = KIND_LID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_APPOINTMENT, &propname.guid);
	/* PidLidAppointmentNotAllowPropose */
	lid = 0x0000825A;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = ((uint32_t)propids.ppropid[0]) << 16 |
								PROPVAL_TYPE_BYTE;
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
		ical_append_line(pcomponent, piline);
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
			if (NULL == pvalue || 0 != strcasecmp(pvalue,
				"IPM.OLE.CLASS.{00061055-0000-0000-C000-000000000046}")) {
				continue;
			}
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
	
	propname.kind = KIND_LID;
	propname.plid = &lid;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	/* PidLidReminderSet */
	lid = 0x00008503;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = ((uint32_t)propids.ppropid[0]) << 16 |
								PROPVAL_TYPE_BYTE;
	pvalue = tpropval_array_get_propval(
				&pmsg->proplist, proptag);
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		pcomponent = ical_new_component("VALARM");
		if (NULL == pcomponent) {
			return FALSE;
		}
		ical_append_component(pical, pcomponent);
		piline = ical_new_simple_line("DESCRIPTION", "REMINDER");
		if (NULL == piline) {
			return FALSE;
		}
		ical_append_line(pcomponent, piline);
		propname.kind = KIND_LID;
		propname.plid = &lid;
		rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
		/* PidLidReminderDelta */
		lid = 0x00008501;
		if (FALSE == get_propids(&propnames, &propids)) {
			return FALSE;
		}
		proptag = ((uint32_t)propids.ppropid[0]) << 16 |
									PROPVAL_TYPE_LONG;
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
		ical_append_line(pcomponent, piline);
		piparam = ical_new_param("RELATED");
		if (NULL == piparam) {
			return FALSE;
		}
		ical_append_param(piline, piparam);
		if (FALSE == ical_append_paramval(piparam, "START")) {
			return FALSE;
		}
		piline = ical_new_simple_line("ACTION", "DISPLAY");
		if (NULL == piline) {
			return FALSE;
		}
		ical_append_line(pcomponent, piline);
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

