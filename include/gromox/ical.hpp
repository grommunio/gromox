#pragma once
#include <ctime>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/double_list.hpp>
#define ICAL_NAME_LEN					64

#define ICAL_FREQUENCY_SECOND			1
#define ICAL_FREQUENCY_MINUTE			2
#define ICAL_FREQUENCY_HOUR				3
#define ICAL_FREQUENCY_DAY				4
#define ICAL_FREQUENCY_WEEK				5
#define ICAL_FREQUENCY_MONTH			6
#define ICAL_FREQUENCY_YEAR				7

#define RRULE_BY_SETPOS					0
#define RRULE_BY_SECOND					1
#define RRULE_BY_MINUTE					2
#define RRULE_BY_HOUR					3
#define RRULE_BY_DAY					4
#define RRULE_BY_MONTHDAY				5
#define RRULE_BY_YEARDAY				6
#define RRULE_BY_WEEKNO					7
#define RRULE_BY_MONTH					8

struct ICAL_COMPONENT {
	DOUBLE_LIST_NODE node;
	char name[ICAL_NAME_LEN];
	DOUBLE_LIST line_list;
	DOUBLE_LIST component_list;
};
using ICAL = ICAL_COMPONENT;

struct ICAL_PARAM {
	DOUBLE_LIST_NODE node;
	char name[ICAL_NAME_LEN];
	DOUBLE_LIST paramval_list;
};

struct ICAL_VALUE {
	DOUBLE_LIST_NODE node;
	char name[ICAL_NAME_LEN];
	DOUBLE_LIST subval_list;
};

struct ICAL_LINE {
	DOUBLE_LIST_NODE node;
	char name[ICAL_NAME_LEN];
	DOUBLE_LIST param_list;
	DOUBLE_LIST value_list;
};

struct ICAL_TIME {
	int year;
	int month;
	int day;
	int hour;
	int minute;
	int second;
	int leap_second;
};

struct ICAL_RRULE {
	int total_count;
	int current_instance;
	ICAL_TIME base_itime;
	ICAL_TIME next_base_itime;
	ICAL_TIME instance_itime;
	BOOL b_until;
	ICAL_TIME until_itime;
	BOOL b_start_exceptional;
	ICAL_TIME real_start_itime;
	int interval;
	int frequency;
	int real_frequency;
	int weekstart;
	BOOL by_mask[9];
	int cur_setpos;
	int setpos_count;
	unsigned char second_bitmap[8];
	unsigned char minute_bitmap[8];
	unsigned char hour_bitmap[3];
	unsigned char wday_bitmap[47];
	unsigned char nwday_bitmap[47];
	unsigned char mday_bitmap[4];
	unsigned char nmday_bitmap[4];
	unsigned char yday_bitmap[46];
	unsigned char nyday_bitmap[46];
	unsigned char week_bitmap[7];
	unsigned char nweek_bitmap[7];
	unsigned char month_bitmap[2];
	unsigned char setpos_bitmap[46];
	unsigned char nsetpos_bitmap[46];
};

void ical_init(ICAL *pical);

void ical_free(ICAL *pical);
extern GX_EXPORT bool ical_retrieve(ICAL *, char *in_buff);
extern GX_EXPORT bool ical_serialize(ICAL *, char *out_buff, size_t maxlen);
ICAL_COMPONENT* ical_new_component(const char *name);

void ical_append_component(ICAL_COMPONENT *pparent, ICAL_COMPONENT *pchild);

ICAL_LINE* ical_new_line(const char *name);

void ical_append_line(ICAL_COMPONENT *pcomponent, ICAL_LINE *piline);
ICAL_LINE* ical_get_line(ICAL_COMPONENT *pcomponent, const char *name);

ICAL_PARAM* ical_new_param(const char*name);
extern GX_EXPORT bool ical_append_paramval(ICAL_PARAM *, const char *paramval);
void ical_append_param(ICAL_LINE *piline, ICAL_PARAM *piparam);

const char* ical_get_first_paramval(ICAL_LINE *piline, const char *name);

ICAL_VALUE* ical_new_value(const char *name);
extern GX_EXPORT bool ical_append_subval(ICAL_VALUE *, const char *subval);
void ical_append_value(ICAL_LINE *piline, ICAL_VALUE *pivalue);

const char* ical_get_first_subvalue_by_name(
	ICAL_LINE *piline, const char *name);

const char* ical_get_first_subvalue(ICAL_LINE *piline);

DOUBLE_LIST* ical_get_subval_list(ICAL_LINE *piline, const char *name);

ICAL_LINE* ical_new_simple_line(const char *name, const char *value);
extern GX_EXPORT bool ical_parse_utc_offset(const char *str_offset, int *phour, int *pminute);
extern GX_EXPORT bool ical_parse_date(const char *str_date, int *pyear, int *pmonth, int *pday);
extern GX_EXPORT bool ical_parse_datetime(const char *str_datetime, bool *pb_utc, ICAL_TIME *pitime);
int ical_get_dayofweek(int year, int month, int day);

int ical_get_dayofyear(int year, int month, int day);

int ical_get_monthdays(int year, int month);

int ical_get_monthweekorder(int day);

int ical_get_negative_monthweekorder(int year, int month, int day);

int ical_get_yearweekorder(int year, int month, int day);

int ical_get_negative_yearweekorder(int year, int month, int day);

int ical_get_dayofmonth(int year, int month, int order, int dayofweek);

void ical_get_itime_from_yearday(int year, int yearday, ICAL_TIME *pitime);
extern GX_EXPORT bool ical_parse_byday(const char *str_byday, int *pdayofweek, int *pweekorder);
extern GX_EXPORT bool ical_parse_duration(const char *str_duration, long *pseconds);
extern GX_EXPORT bool ical_itime_to_utc(ICAL_COMPONENT *, ICAL_TIME, time_t *);
extern GX_EXPORT bool ical_datetime_to_utc(ICAL_COMPONENT *, const char *datetime, time_t *);
extern GX_EXPORT bool ical_utc_to_datetime(ICAL_COMPONENT *, time_t utc_time, ICAL_TIME *);
int ical_cmp_time(ICAL_TIME itime1, ICAL_TIME itime2);

void ical_add_year(ICAL_TIME *pitime, int years);
void ical_add_month(ICAL_TIME *pitime, int months);
void ical_add_day(ICAL_TIME *pitime, int days);

void ical_subtract_day(ICAL_TIME *pitime, int days);

int ical_delta_day(ICAL_TIME itime1, ICAL_TIME itime2);

void ical_add_hour(ICAL_TIME *pitime, int hours);
void ical_add_minute(ICAL_TIME *pitime, int minutes);
void ical_add_second(ICAL_TIME *pitime, int seconds);
extern GX_EXPORT bool ical_parse_rrule(ICAL_COMPONENT *, time_t start, DOUBLE_LIST *value_list, ICAL_RRULE *);
extern GX_EXPORT bool ical_rrule_iterate(ICAL_RRULE *);
int ical_rrule_weekstart(ICAL_RRULE *pirrule);
extern GX_EXPORT bool ical_rrule_endless(ICAL_RRULE *);
const ICAL_TIME* ical_rrule_until_itime(ICAL_RRULE *pirrule);

int ical_rrule_total_count(ICAL_RRULE *pirrule);
extern GX_EXPORT bool ical_rrule_exceptional(ICAL_RRULE *);
ICAL_TIME ical_rrule_base_itime(ICAL_RRULE *pirrule);

int ical_rrule_sequence(ICAL_RRULE *pirrule);

ICAL_TIME ical_rrule_instance_itime(ICAL_RRULE *pirrule);

int ical_rrule_interval(ICAL_RRULE *pirrule);

int ical_rrule_frequency(ICAL_RRULE *pirrule);
extern GX_EXPORT bool ical_rrule_check_bymask(ICAL_RRULE *, int rrule_by);
