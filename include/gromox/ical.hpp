#pragma once
#include <ctime>
#include <list>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#define ICAL_NAME_LEN					64

enum class ical_frequency {
	second, minute, hour, day, week, month, year, invalid,
};

enum class rrule_by {
	setpos = 0, second, minute, hour, day, monthday, yearday, weekno, month,
};

struct GX_EXPORT ical_param {
	public:
	ical_param(const char *n) : name(gromox::znul(n)) {}
	void append_paramval(const char *s) { paramval_list.emplace_back(gromox::znul(s)); }

	std::string name;
	std::vector<std::string> paramval_list;
};

struct GX_EXPORT ical_value {
	public:
	ical_value() = default;
	ical_value(const char *n) : name(gromox::znul(n)) {}
	void append_subval(const char *s) { subval_list.emplace_back(gromox::znul(s)); }
	void append_subval(std::string &&s) { subval_list.emplace_back(std::move(s)); }

	std::string name;
	std::vector<std::string> subval_list;
};

struct GX_EXPORT ical_line {
	public:
	ical_line(const char *n) : m_name(n) {}
	ical_line(const char *n, const char *v);
	ical_line(const char *n, std::string &&v);
	ical_param &append_param(ical_param &&o) { param_list.push_back(std::move(o)); return param_list.back(); }
	void append_param(const char *v, const char *pv);
	ical_value &append_value(ical_value &&o) { value_list.push_back(std::move(o)); return value_list.back(); }
	ical_value &append_value() { return value_list.emplace_back(); }
	ical_value &append_value(const char *v) { value_list.push_back(ical_value(v)); return value_list.back(); }
	void append_value(const char *v, const char *sv);
	void append_value(const char *v, std::string &&sv);
	const char *get_first_paramval(const char *name) const;
	const char *get_first_subvalue() const;
	const char *get_first_subvalue_by_name(const char *name) const;
	const std::vector<std::string> *get_subval_list(const char *name) const;

	std::string m_name;
	std::vector<ical_param> param_list;
	std::vector<ical_value> value_list;
};

struct GX_EXPORT ical_component {
	public:
	ical_component(const char *n) : m_name(n) {}
	ical_component &append_comp(const char *n) { return component_list.emplace_back(n); }
	ical_line &append_line(ical_line &&o) { return line_list.emplace_back(std::move(o)); }
	ical_line &append_line(const char *n) { return line_list.emplace_back(n); }
	ical_line &append_line(const char *n, const char *v) { return line_list.emplace_back(n, v); }
	ical_line &append_line(const char *n, std::string &&v) { return line_list.emplace_back(n, std::move(v)); }
	const ical_line *get_line(const char *name) const;

	std::string m_name;
	std::vector<ical_line> line_list;
	/* Be wary of iterator/pointer invalidation */
	std::list<ical_component> component_list;
};

struct GX_EXPORT ical : public ical_component {
	ical() : ical_component("VCALENDAR") {}
	bool load_from_str_move(char *in_buff);
	ec_error_t serialize(std::string &out) const;
};

enum itime_type : uint8_t {
	unspec, utc, floating, floating_day, local,
};

struct GX_EXPORT ical_time {
	int twcompare(const ical_time &other) const;
	inline bool operator<(const ical_time &o) const { return twcompare(o) < 0; }
	inline bool operator<=(const ical_time &o) const { return twcompare(o) <= 0; }
	inline bool operator>(const ical_time &o) const { return twcompare(o) > 0; }
	inline bool operator>=(const ical_time &o) const { return twcompare(o) >= 0; }
	void add_year(int ys);
	void add_month(int ms);
	void add_day(int ds);
	void subtract_day(int ds);
	void add_hour(int);
	void add_minute(int);
	void add_second(int);
	int delta_day(ical_time) const;
	std::string fmt() const;

	int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0, leap_second = 0;
	itime_type type = itime_type::unspec;
};

struct GX_EXPORT ical_rrule {
	bool iterate();
	inline bool endless() const { return total_count == 0 && !b_until; }
	inline const ical_time *get_until_itime() const { return b_until ? &until_itime : nullptr; }
	inline int sequence() const { return current_instance; }
	inline bool test_bymask(rrule_by x) const { return by_mask[static_cast<size_t>(x)]; }
	inline void set_bymask(rrule_by x) { by_mask[static_cast<size_t>(x)] = true; }

	int total_count;
	int current_instance;
	ical_time base_itime, next_base_itime, instance_itime, until_itime;
	ical_time real_start_itime;
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

extern GX_EXPORT bool ical_parse_utc_offset(const char *str_offset, int *phour, int *pminute);
extern GX_EXPORT bool ical_parse_date(const char *in, ical_time *out);
extern GX_EXPORT bool ical_parse_datetime(const char *in, ical_time *out);
extern GX_EXPORT unsigned int ical_get_dayofweek(unsigned int year, unsigned int month, unsigned int day);
extern GX_EXPORT unsigned int ical_get_dayofyear(unsigned int year, unsigned int month, unsigned int day);
extern GX_EXPORT unsigned int ical_get_monthdays(unsigned int year, unsigned int month);
extern GX_EXPORT int ical_get_monthweekorder(int day);
extern GX_EXPORT int ical_get_dayofmonth(int year, int month, int order, int dayofweek);
extern GX_EXPORT void ical_get_itime_from_yearday(int year, int yearday, ical_time *pitime);
extern GX_EXPORT bool ical_parse_byday(const char *str_byday, int *pdayofweek, int *pweekorder);
extern GX_EXPORT bool ical_parse_duration(const char *str_duration, long *pseconds);
extern GX_EXPORT bool ical_itime_to_utc(const ical_component *, ical_time, time_t *);
extern GX_EXPORT bool ical_datetime_to_utc(const ical_component *, const char *datetime, time_t *);
extern GX_EXPORT bool ical_utc_to_datetime(const ical_component *, time_t utc_time, ical_time *);
extern GX_EXPORT const char *ical_parse_rrule(const ical_component *, time_t start, const std::vector<ical_value> *, ical_rrule *);
extern GX_EXPORT int weekday_to_int(const char *);
extern GX_EXPORT const char *weekday_to_str(unsigned int);
