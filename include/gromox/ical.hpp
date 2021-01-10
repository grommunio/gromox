#pragma once
#ifdef __cplusplus
#	include <ctime>
#else
#	include <time.h>
#endif
#include <gromox/common_types.hpp>
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

typedef struct _ICAL_COMPONENT {
	DOUBLE_LIST_NODE node;
	char name[ICAL_NAME_LEN];
	DOUBLE_LIST line_list;
	DOUBLE_LIST component_list;
} ICAL_COMPONENT, ICAL;

typedef struct _ICAL_PARAM {
	DOUBLE_LIST_NODE node;
	char name[ICAL_NAME_LEN];
	DOUBLE_LIST paramval_list;
} ICAL_PARAM;

typedef struct _ICAL_VALUE {
	DOUBLE_LIST_NODE node;
	char name[ICAL_NAME_LEN];
	DOUBLE_LIST subval_list;
} ICAL_VALUE;

typedef struct _ICAL_LINE {
	DOUBLE_LIST_NODE node;
	char name[ICAL_NAME_LEN];
	DOUBLE_LIST param_list;
	DOUBLE_LIST value_list;
} ICAL_LINE;

typedef struct _ICAL_TIME {
	int year;
	int month;
	int day;
	int hour;
	int minute;
	int second;
	int leap_second;
} ICAL_TIME;

typedef struct _ICAL_RRULE {
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
} ICAL_RRULE;

#ifdef __cplusplus
extern "C" {
#endif

void ical_init(ICAL *pical);

void ical_free(ICAL *pical);

BOOL ical_retrieve(ICAL *pical, char *in_buff);

BOOL ical_serialize(ICAL *pical, char *out_buff, size_t max_length);

ICAL_COMPONENT* ical_new_component(const char *name);

void ical_append_component(ICAL_COMPONENT *pparent, ICAL_COMPONENT *pchild);

ICAL_LINE* ical_new_line(const char *name);

void ical_append_line(ICAL_COMPONENT *pcomponent, ICAL_LINE *piline);
ICAL_LINE* ical_get_line(ICAL_COMPONENT *pcomponent, const char *name);

ICAL_PARAM* ical_new_param(const char*name);

BOOL ical_append_paramval(ICAL_PARAM *piparam, const char *paramval);

void ical_append_param(ICAL_LINE *piline, ICAL_PARAM *piparam);

const char* ical_get_first_paramval(ICAL_LINE *piline, const char *name);

ICAL_VALUE* ical_new_value(const char *name);

BOOL ical_append_subval(ICAL_VALUE *pivalue, const char *subval);

void ical_append_value(ICAL_LINE *piline, ICAL_VALUE *pivalue);

const char* ical_get_first_subvalue_by_name(
	ICAL_LINE *piline, const char *name);

const char* ical_get_first_subvalue(ICAL_LINE *piline);

DOUBLE_LIST* ical_get_subval_list(ICAL_LINE *piline, const char *name);

ICAL_LINE* ical_new_simple_line(const char *name, const char *value);

BOOL ical_parse_utc_offset(const char *str_offset,
	int *phour, int *pminute);

BOOL ical_parse_date(const char *str_date,
	int *pyear, int *pmonth, int *pday);

BOOL ical_parse_datetime(const char *str_datetime,
	BOOL *pb_utc, ICAL_TIME *pitime);

int ical_get_dayofweek(int year, int month, int day);

int ical_get_dayofyear(int year, int month, int day);

int ical_get_monthdays(int year, int month);

int ical_get_monthweekorder(int day);

int ical_get_negative_monthweekorder(int year, int month, int day);

int ical_get_yearweekorder(int year, int month, int day);

int ical_get_negative_yearweekorder(int year, int month, int day);

int ical_get_dayofmonth(int year, int month, int order, int dayofweek);

void ical_get_itime_from_yearday(int year, int yearday, ICAL_TIME *pitime);

BOOL ical_parse_byday(const char *str_byday,
	int *pdayofweek, int *pweekorder);

BOOL ical_parse_duration(const char *str_duration, long *pseconds);

BOOL ical_itime_to_utc(ICAL_COMPONENT *ptz_component,
	ICAL_TIME itime, time_t *ptime);

BOOL ical_datetime_to_utc(ICAL_COMPONENT *ptz_component,
	const char *str_datetime, time_t *ptime);
BOOL ical_utc_to_datetime(ICAL_COMPONENT *ptz_component,
	time_t utc_time, ICAL_TIME *pitime);

int ical_cmp_time(ICAL_TIME itime1, ICAL_TIME itime2);

void ical_add_year(ICAL_TIME *pitime, int years);
void ical_add_month(ICAL_TIME *pitime, int months);
void ical_add_day(ICAL_TIME *pitime, int days);

void ical_subtract_day(ICAL_TIME *pitime, int days);

int ical_delta_day(ICAL_TIME itime1, ICAL_TIME itime2);

void ical_add_hour(ICAL_TIME *pitime, int hours);
void ical_add_minute(ICAL_TIME *pitime, int minutes);
void ical_add_second(ICAL_TIME *pitime, int seconds);
BOOL ical_parse_rrule(ICAL_COMPONENT *ptz_component,
	time_t start_time, DOUBLE_LIST *pvalue_list, ICAL_RRULE *pirrule);

BOOL ical_rrule_iterate(ICAL_RRULE *pirrule);

int ical_rrule_weekstart(ICAL_RRULE *pirrule);

BOOL ical_rrule_endless(ICAL_RRULE *pirrule);

const ICAL_TIME* ical_rrule_until_itime(ICAL_RRULE *pirrule);

int ical_rrule_total_count(ICAL_RRULE *pirrule);

BOOL ical_rrule_exceptional(ICAL_RRULE *pirrule);

ICAL_TIME ical_rrule_base_itime(ICAL_RRULE *pirrule);

int ical_rrule_sequence(ICAL_RRULE *pirrule);

ICAL_TIME ical_rrule_instance_itime(ICAL_RRULE *pirrule);

int ical_rrule_interval(ICAL_RRULE *pirrule);

int ical_rrule_frequency(ICAL_RRULE *pirrule);
BOOL ical_rrule_check_bymask(ICAL_RRULE *pirrule, int rrule_by);

#ifdef __cplusplus
}
#endif
