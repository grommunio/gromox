#pragma once
#include <ctime>
#include <memory>
#include <string>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#define ICAL_NAME_LEN					64

enum class ical_frequency {
	second, minute, hour, day, week, month, year,
};

#define RRULE_BY_SETPOS					0
#define RRULE_BY_SECOND					1
#define RRULE_BY_MINUTE					2
#define RRULE_BY_HOUR					3
#define RRULE_BY_DAY					4
#define RRULE_BY_MONTHDAY				5
#define RRULE_BY_YEARDAY				6
#define RRULE_BY_WEEKNO					7
#define RRULE_BY_MONTH					8

struct GX_EXPORT ical_param {
	public:
	ical_param(const char *n) : name(gromox::znul(n)) {}
	void append_paramval(const char *s) { paramval_list.emplace_back(gromox::znul(s)); }

	std::string name;
	std::vector<std::string> paramval_list;
};
using ICAL_PARAM = ical_param;

struct GX_EXPORT ical_value {
	public:
	ical_value() = default;
	ical_value(const char *n) : name(gromox::znul(n)) {}
	void append_subval(const char *s) { subval_list.emplace_back(gromox::znul(s)); }

	std::string name;
	std::vector<std::string> subval_list;
};
using ICAL_VALUE = ical_value;

struct GX_EXPORT ical_line {
	public:
	ical_param &append_param(ical_param &&o) { param_list.push_back(std::move(o)); return param_list.back(); }
	void append_param(const char *v, const char *pv);
	ical_value &append_value(ical_value &&o) { value_list.push_back(std::move(o)); return value_list.back(); }
	ical_value &append_value() { return value_list.emplace_back(); }
	ical_value &append_value(const char *v) { value_list.push_back(ical_value(v)); return value_list.back(); }
	void append_value(const char *v, const char *sv);
	const char *get_first_paramval(const char *name);
	const char *get_first_subvalue();
	const char *get_first_subvalue_by_name(const char *name);
	const std::vector<std::string> *get_subval_list(const char *name);

	std::string m_name;
	std::vector<ical_param> param_list;
	std::vector<ical_value> value_list;
};
using ICAL_LINE = ical_line;

struct GX_EXPORT ical_component {
	public:
	int append_comp(std::shared_ptr<ical_component>);
	int append_line(std::shared_ptr<ICAL_LINE>);
	std::shared_ptr<ICAL_LINE> get_line(const char *name);

	std::string m_name;
	std::vector<std::shared_ptr<ICAL_LINE>> line_list;
	std::vector<std::shared_ptr<ical_component>> component_list;
};
using ICAL_COMPONENT = ical_component;

struct GX_EXPORT ical : public ical_component {
	int init();
	bool retrieve(char *in_buff);
	bool serialize(char *out_buff, size_t maxlen);
};
using ICAL = ical;

struct ICAL_TIME {
	int twcompare(const ICAL_TIME &other) const;
	inline bool operator<(const ICAL_TIME &o) const { return twcompare(o) < 0; }
	inline bool operator<=(const ICAL_TIME &o) const { return twcompare(o) <= 0; }
	inline bool operator>(const ICAL_TIME &o) const { return twcompare(o) > 0; }
	inline bool operator>=(const ICAL_TIME &o) const { return twcompare(o) >= 0; }
	void add_year(int ys);
	void add_month(int ms);
	void add_day(int ds);
	void subtract_day(int ds);
	void add_hour(int);
	void add_minute(int);
	void add_second(int);
	int delta_day(ICAL_TIME) const;

	int year;
	int month;
	int day;
	int hour;
	int minute;
	int second;
	int leap_second;
};

struct GX_EXPORT ical_rrule {
	bool iterate();
	inline bool endless() const { return total_count == 0 && !b_until; }
	inline const ICAL_TIME *get_until_itime() const { return b_until ? &until_itime : nullptr; }
	inline int sequence() const { return current_instance; }
	inline bool check_bymask(unsigned int rrule_by) const { return by_mask[rrule_by]; }

	int total_count;
	int current_instance;
	ICAL_TIME base_itime;
	ICAL_TIME next_base_itime;
	ICAL_TIME instance_itime;
	ICAL_TIME until_itime;
	ICAL_TIME real_start_itime;
	bool b_until, b_start_exceptional, by_mask[9];
	int interval;
	ical_frequency frequency, real_frequency;
	int weekstart;
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
using ICAL_RRULE = ical_rrule;

extern GX_EXPORT std::shared_ptr<ICAL_COMPONENT> ical_new_component(const char *name);
extern GX_EXPORT std::shared_ptr<ICAL_LINE> ical_new_line(const char *name);
extern GX_EXPORT std::shared_ptr<ICAL_LINE> ical_new_simple_line(const char *name, const char *value);
extern GX_EXPORT bool ical_parse_utc_offset(const char *str_offset, int *phour, int *pminute);
extern GX_EXPORT bool ical_parse_date(const char *str_date, int *pyear, int *pmonth, int *pday);
extern GX_EXPORT bool ical_parse_datetime(const char *str_datetime, bool *pb_utc, ICAL_TIME *pitime);
extern GX_EXPORT unsigned int ical_get_dayofweek(unsigned int year, unsigned int month, unsigned int day);
extern GX_EXPORT unsigned int ical_get_dayofyear(unsigned int year, unsigned int month, unsigned int day);
extern GX_EXPORT unsigned int ical_get_monthdays(unsigned int year, unsigned int month);
int ical_get_monthweekorder(int day);
int ical_get_negative_monthweekorder(int year, int month, int day);
int ical_get_yearweekorder(int year, int month, int day);
int ical_get_negative_yearweekorder(int year, int month, int day);
int ical_get_dayofmonth(int year, int month, int order, int dayofweek);
void ical_get_itime_from_yearday(int year, int yearday, ICAL_TIME *pitime);
extern GX_EXPORT bool ical_parse_byday(const char *str_byday, int *pdayofweek, int *pweekorder);
extern GX_EXPORT bool ical_parse_duration(const char *str_duration, long *pseconds);
extern GX_EXPORT bool ical_itime_to_utc(std::shared_ptr<ICAL_COMPONENT>, ICAL_TIME, time_t *);
extern GX_EXPORT bool ical_datetime_to_utc(std::shared_ptr<ICAL_COMPONENT>, const char *datetime, time_t *);
extern GX_EXPORT bool ical_utc_to_datetime(std::shared_ptr<ICAL_COMPONENT>, time_t utc_time, ICAL_TIME *);
extern GX_EXPORT bool ical_parse_rrule(std::shared_ptr<ICAL_COMPONENT>, time_t start, const std::vector<ical_value> *, ICAL_RRULE *);
extern GX_EXPORT int weekday_to_int(const char *);
extern GX_EXPORT const char *weekday_to_str(unsigned int);
