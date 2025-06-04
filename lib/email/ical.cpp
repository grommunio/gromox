// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <vector>
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/ical.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/util.hpp>
#define MAX_LINE 75

using namespace gromox;

namespace {

struct LINE_ITEM {
	char *ptag;
	char *pvalue;
};

}

static char* ical_get_tag_comma(char *pstring)
{
	int i;
	int tmp_len;
	BOOL b_quote;
	
	b_quote = FALSE;
	tmp_len = strlen(pstring);
	for (i=0; i<tmp_len; i++) {
		if (b_quote) {
			if ('"' == pstring[i]) {
				memmove(pstring + i, pstring + i + 1, tmp_len - i);
				pstring[tmp_len] = '\0';
				tmp_len --;
				i --;
				b_quote = FALSE;
			}
			continue;
		}
		if ('"' == pstring[i]) {
			memmove(pstring + i, pstring + i + 1, tmp_len - i);
			pstring[tmp_len] = '\0';
			tmp_len --;
			i --;
			b_quote = TRUE;
		} else if (',' == pstring[i]) {
			pstring[i] = '\0';
			return pstring + i + 1;
		}
	}
	return NULL;
}

static char* ical_get_tag_semicolon(char *pstring)
{
	int i;
	int tmp_len;
	BOOL b_quote;
	
	b_quote = FALSE;
	tmp_len = strlen(pstring);
	for (i=0; i<tmp_len; i++) {
		if (b_quote) {
			if (pstring[i] == '"')
				b_quote = FALSE;
			continue;
		}
		if ('"' == pstring[i]) {
			b_quote = TRUE;
		} else if (';' == pstring[i]) {
			pstring[i] = '\0';
			for (i += 1; i < tmp_len; ++i)
				if (pstring[i] != ' ' && pstring[i] != '\t')
					break;
			return pstring + i;
		}
	}
	return NULL;
}

static char *ical_get_value_sep(char *pstring, char sep)
{
	int i;
	int tmp_len;
	
	tmp_len = strlen(pstring);
	for (i=0; i<tmp_len; i++) {
		if ('\\' == pstring[i]) {
			if (pstring[i+1] == '\\' || pstring[i+1] == sep) {
				memmove(pstring + i, pstring + i + 1, tmp_len - i - 1);
				pstring[tmp_len-1] = '\0';
				tmp_len --;
			} else if ('n' == pstring[i + 1] || 'N' == pstring[i + 1]) {
				pstring[i] = '\r';
				pstring[i + 1] = '\n';
			}
		} else if (pstring[i] == sep) {
			pstring[i] = '\0';
			for (i += 1; i < tmp_len; ++i)
				if (pstring[i] != ' ' && pstring[i] != '\t')
					break;
			return pstring + i;
		}
	}
	return NULL;
}

static void ical_clear_component(ical_component *pcomponent)
{
	pcomponent->component_list.clear();
}

static bool ical_retrieve_line_item(char *pline, LINE_ITEM *pitem)
{
	BOOL b_quote;
	BOOL b_value;
	pitem->ptag = NULL;
	pitem->pvalue = NULL;
	
	b_value = FALSE;
	b_quote = FALSE;
	while ('\0' != *pline) {
		if ((pitem->ptag == nullptr || (b_value && pitem->pvalue == nullptr)) &&
		    (*pline == ' ' || *pline == '\t')) {
			pline ++;
			continue;
		}
		if (NULL == pitem->ptag) {
			pitem->ptag = pline++;
			continue;
		}
		if (!b_value) {
			if (*pline == '"')
				b_quote = b_quote ? false : TRUE;
			if (b_quote) {
				pline ++;
				continue;
			}
			if (':' == *pline) {
				*pline = '\0';
				b_value = TRUE;
			}
		} else {
			if (NULL == pitem->pvalue) {
				pitem->pvalue = pline;
				break;
			}
		}
		pline ++;
	}
	return pitem->ptag != nullptr;
}

static char* ical_get_string_line(char *pbuff, size_t max_length)
{
	size_t i;
	char *pnext;
	bool b_searched = false;

	for (i=0; i<max_length; i++) {
		if ('\r' == pbuff[i]) {
			pbuff[i] = '\0';
			if (!b_searched)
				b_searched = true;
			if (i + 1 < max_length && '\n' == pbuff[i + 1]) {
				pnext = pbuff + i + 2;
				if (' ' == *pnext || '\t' == *pnext) {
					pnext ++;
					size_t bytes = pbuff + max_length - pnext;
					memmove(pbuff + i, pnext, bytes);
					pbuff[i+bytes] = '\0';
					max_length -= pnext - (pbuff + i);
					continue;
				}
			} else {
				pnext = pbuff + i + 1;
				if (' ' == *pnext || '\t' == *pnext) {
					pnext ++;
					size_t bytes = pbuff + max_length - pnext;
					memmove(pbuff + i, pnext, bytes);
					pbuff[i+bytes] = '\0';
					max_length -= pnext - (pbuff + i);
					continue;
				}
			}
			return pnext;
		} else if ('\n' == pbuff[i]) {
			pbuff[i] = '\0';
			if (!b_searched)
				b_searched = true;
			pnext = pbuff + i + 1;
			if (' ' == *pnext || '\t' == *pnext) {
				pnext ++;
				size_t bytes = pbuff + max_length - pnext;
				memmove(pbuff + i, pnext, bytes);
				pbuff[i+bytes] = '\0';
				max_length -= pnext - (pbuff + i);
				continue;
			}
			return pnext;
		}
	}
	return NULL;
}

static bool empty_line(const char *pline)
{	
	for (; *pline != '\0'; ++pline)
		if (*pline != ' ' && *pline != '\t')
			return false;
	return true;
}

static ical_param ical_retrieve_param(char *ptag)
{
	char *ptr;
	char *pnext;
	
	ptr = strchr(ptag, '=');
	if (ptr != nullptr)
		*ptr = '\0';
	ical_param piparam(ptag);
	if (ptr == nullptr)
		return piparam;
	++ptr;
	do {
		pnext = ical_get_tag_comma(ptr);
		piparam.append_paramval(ptr);
	} while ((ptr = pnext) != NULL);
	return piparam;
}

static ical_line ical_retrieve_tag(char *ptag)
{
	char *ptr;
	char *pnext;
	
	ptr = strchr(ptag, ';');
	if (ptr != nullptr)
		*ptr = '\0';
	ical_line piline(ptag);
	if (ptr == nullptr)
		return piline;
	ptr ++;
	do {
		pnext = ical_get_tag_semicolon(ptr);
		piline.append_param(ical_retrieve_param(ptr));
	} while ((ptr = pnext) != NULL);
	return piline;
}

static bool ical_check_base64(ical_line *piline)
{
	const auto &y = piline->param_list;
	return std::any_of(y.cbegin(), y.cend(),
	       [](const auto &e) { return strcasecmp(e.name.c_str(), "ENCODING") == 0; });
}

static BOOL ical_retrieve_value(ical_line *piline, char *pvalue) try
{
	char *ptr;
	char *ptr1;
	char *pnext;
	char *pnext1;
	
	auto b_base64 = ical_check_base64(piline);
	ptr = pvalue;
	do {
		pnext = ical_get_value_sep(ptr, ';');
		if (!b_base64) {
			ptr1 = strchr(ptr, '=');
			if (ptr1 != nullptr)
				*ptr1 = '\0';
		} else {
			ptr1 = NULL;
		}
		ical_value *pivalue;
		if (NULL == ptr1) {
			pivalue = &piline->append_value();
			ptr1 = ptr;
		} else {
			pivalue = &piline->append_value(ptr);
			ptr1 ++;
		}
		do {
			pnext1 = ical_get_value_sep(ptr1, ',');
			pivalue->append_subval(*ptr1 == '\0' ? nullptr : ptr1);
		} while ((ptr1 = pnext1) != NULL);
	} while ((ptr = pnext) != NULL);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2099: ENOMEM");
	return false;
}

static void ical_unescape_string(char *pstring)
{
	int i;
	int tmp_len;
	
	tmp_len = strlen(pstring);
	for (i=0; i<tmp_len; i++) {
		if ('\\' == pstring[i]) {
			if ('\\' == pstring[i + 1] || ';' == pstring[i + 1] ||
				',' == pstring[i + 1]) {
				memmove(pstring + i, pstring + i + 1, tmp_len - i);
				pstring[tmp_len] = '\0';
				tmp_len --;
			} else if ('n' == pstring[i + 1] || 'N' == pstring[i + 1]) {
				pstring[i] = '\r';
				pstring[i + 1] = '\n';
			}
		}
	}
}

static inline bool ical_std_keyword(const char *s)
{
	return strcasecmp(s, "ATTACH") == 0 || strcasecmp(s, "COMMENT") == 0 ||
	       strcasecmp(s, "DESCRIPTION") == 0 || strcasecmp(s, "X-ALT-DESC") == 0 ||
	       strcasecmp(s, "LOCATION") == 0 || strcasecmp(s, "SUMMARY") == 0 ||
	       strcasecmp(s, "CONTACT") == 0 || strcasecmp(s, "URL") == 0 ||
	       strcasecmp(s, "UID") == 0 || strcasecmp(s, "TZNAME") == 0 ||
	       strcasecmp(s, "TZURL") == 0 || strcasecmp(s, "PRODID") == 0 ||
	       strcasecmp(s, "VERSION") == 0;
}

static bool ical_retrieve_component(ical_component &comp,
    char *in_buff, char **ppnext) try
{
	auto pcomponent = &comp;
	char *pline;
	char *pnext;
	size_t length;
	LINE_ITEM tmp_item;
	
	ical_clear_component(pcomponent);
	pline = in_buff;
	length = strlen(in_buff);
	do {
		pnext = ical_get_string_line(pline, length - (pline - in_buff));
		if (empty_line(pline))
			continue;
		if (!ical_retrieve_line_item(pline, &tmp_item))
			break;
		if (0 == strcasecmp(tmp_item.ptag, "BEGIN")) {
			if (tmp_item.pvalue == nullptr)
				break;
			auto &pcomponent1 = pcomponent->append_comp(tmp_item.pvalue);
			if (!ical_retrieve_component(pcomponent1, pnext, &pnext))
				break;
			continue;
		}
		if (0 == strcasecmp(tmp_item.ptag, "END")) {
			if (tmp_item.pvalue == nullptr ||
			    strcasecmp(pcomponent->m_name.c_str(), tmp_item.pvalue) != 0)
				break;
			if (ppnext != nullptr)
				*ppnext = pnext;
			return true;
		}
		auto piline = &pcomponent->append_line(ical_retrieve_tag(tmp_item.ptag));
		if (tmp_item.pvalue == nullptr)
			continue;
		if (ical_std_keyword(piline->m_name.c_str())) {
			auto &pivalue = piline->append_value();
			ical_unescape_string(tmp_item.pvalue);
			pivalue.append_subval(tmp_item.pvalue);
		} else if (!ical_retrieve_value(piline, tmp_item.pvalue)) {
			break;
		}
	} while ((pline = pnext) != NULL);
	ical_clear_component(pcomponent);
	return false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2098: ENOMEM");
	return false;
}

bool ical::load_from_str_move(char *in_buff)
{
	auto pical = this;
	char *pline;
	char *pnext;
	size_t length;
	LINE_ITEM tmp_item;
	
	ical_clear_component(pical);
	pnext = in_buff;
	length = strlen(in_buff);
	do {
		pline = pnext;
		pnext = ical_get_string_line(pline, length - (pline - in_buff));
		if (NULL == pnext) {
			ical_clear_component(pical);
			return false;
		}
	} while (empty_line(pline));
	if (!ical_retrieve_line_item(pline, &tmp_item)) {
		ical_clear_component(pical);
		return false;
	}
	if (0 == strcasecmp(tmp_item.ptag, "BEGIN") &&
		NULL != pnext && (NULL != tmp_item.pvalue &&
		0 == strcasecmp(tmp_item.pvalue, "VCALENDAR"))) {
		return ical_retrieve_component(*pical, pnext, nullptr);
	}
	ical_clear_component(pical);
	return false;
}

static std::string ical_serialize_value_string(size_t &line_offset,
    const std::string &s)
{
	std::string out;
	for (size_t i = 0; i < s.size(); ++i) {
		auto w = utf8_byte_num[static_cast<uint8_t>(s[i])];
		if (w == 0)
			w = 1;
		if (s[i] == '\n' || (s[i] == '\r' && s[i+1] == '\n')) {
			if (line_offset + 2 > MAX_LINE) {
				out += "\r\n ";
				line_offset = 1;
			}
			out += "\\n";
			line_offset += 2;
			if (s[i] == '\r')
				++i;
			continue;
		} else if (s[i] == '\\' || s[i] == ';' || s[i] == ',') {
			if (line_offset + w + 1 > MAX_LINE) {
				out += "\r\n ";
				line_offset = 1;
			}
			out += '\\';
			out += s[i];
			line_offset += 2;
			continue;
		}
		if (line_offset + w > MAX_LINE) {
			out += "\r\n ";
			line_offset = 1;
		}
		out += s[i];
		++line_offset;
	}
	return out;
}

static std::string ical_serialize_component(const ical_component &com)
{
	std::string out_buff;
	auto pcomponent = &com;	
	out_buff += "BEGIN:" + com.m_name + "\r\n";
	for (const auto &line : com.line_list) {
		std::string out_line = line.m_name;
		for (const auto &piparam : line.param_list) {
			out_line += ';';
			out_line += piparam.name;
			out_line += '=';
			bool need_comma = false;
			for (const auto &pdata2 : piparam.paramval_list) {
				if (need_comma)
					out_line += ',';
				need_comma = true;
				if (strpbrk(pdata2.c_str(), ",:;") == nullptr)
					out_line += pdata2;
				else
					out_line += "\"" + pdata2 + "\"";
			}
		}
		out_line += ':';
		bool need_semicolon = false;
		auto line_length = out_line.size();
		for (const auto &pivalue : line.value_list) {
			if (need_semicolon) {
				out_line += ';';
				++line_length;
			}
			need_semicolon = true;
			if (pivalue.name.size() > 0) {
				out_line += pivalue.name;
				out_line += '=';
				line_length += pivalue.name.size() + 1;
			}
			bool need_comma = false;
			for (const auto &pnv2 : pivalue.subval_list) {
				if (need_comma) {
					out_line += ',';
					++line_length;
				}
				need_comma = true;
				if (pnv2.empty())
					continue;
				out_line += ical_serialize_value_string(line_length, pnv2);
			}
		}
		out_buff += std::move(out_line);
		out_buff += "\r\n";
	}
	for (const auto &comp : pcomponent->component_list)
		out_buff += ical_serialize_component(comp);
	out_buff += "END:" + pcomponent->m_name + "\r\n";
	return out_buff;
}

ec_error_t ical::serialize(std::string &out) const try
{
	out = ical_serialize_component(*this);
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecMAPIOOM;
}

static const std::vector<std::string> *
ical_get_subval_list_internal(const std::vector<ical_value> *pvalue_list,
    const char *name)
{
	auto end = pvalue_list->cend();
	auto it  = std::find_if(pvalue_list->cbegin(), end,
	           [=](const auto &e) { return strcasecmp(e.name.c_str(), name) == 0; });
	if (it == end)
		return nullptr;
	return &it->subval_list;
}

static const char *ical_get_first_subvalue_by_name_internal(
    const std::vector<ical_value> *pvalue_list, const char *name)
{
	if (*name == '\0')
		return NULL;
	auto plist = ical_get_subval_list_internal(pvalue_list, name);
	if (plist == nullptr)
		return NULL;
	return plist->size() == 1 ? plist->front().c_str() : nullptr;
}

const char *ical_line::get_first_subvalue_by_name(const char *name) const
{
	return ical_get_first_subvalue_by_name_internal(&value_list, name);
}

const char *ical_line::get_first_subvalue() const
{
	if (value_list.size() == 0)
		return NULL;
	const auto &pivalue = value_list.front();
	if (pivalue.name[0] != '\0' || pivalue.subval_list.size() != 1)
		return NULL;
	return pivalue.subval_list.front().c_str();
}

const std::vector<std::string> *ical_line::get_subval_list(const char *name) const
{
	return ical_get_subval_list_internal(&value_list, name);
}

/**
 * @str_offset: "-HHMM" or "+HHMM"
 *
 * Split str_offset and validate hour/minute pair for being in range.
 */
bool ical_parse_utc_offset(const char *str_zone, int *phour, int *pminute)
{
	int factor;
	
	*phour = *pminute = 0;
	while (HX_isspace(*str_zone))
		++str_zone;
	if (*str_zone == '-')
		factor = 1;
	else if (*str_zone == '+')
		factor = -1;
	else
		return false;
	if (!HX_isdigit(str_zone[1]) || !HX_isdigit(str_zone[2]) ||
	    !HX_isdigit(str_zone[3]) || !HX_isdigit(str_zone[4]))
		return false;
	int hour   = (str_zone[1] - '0') * 10 + (str_zone[2] - '0');
	int minute = (str_zone[3] - '0') * 10 + (str_zone[4] - '0');
	if (hour < 0 || hour > 23 || minute < 0 || minute > 59)
		return false;
	*phour = factor * hour;
	*pminute = factor * minute;
	return true;
}

bool ical_parse_date(const char *str_date, ical_time *itime)
{
	char tmp_buff[10];
	
	while (HX_isspace(*str_date))
		++str_date;
	gx_strlcpy(tmp_buff, str_date, std::size(tmp_buff));
	*itime = {};
	itime->type = ICT_FLOAT_DAY;
	return strlen(tmp_buff) == 8 &&
	       sscanf(tmp_buff, "%04d%02d%02d", &itime->year, &itime->month, &itime->day) == 3;
}

bool ical_parse_datetime(const char *str_datetime, ical_time *pitime)
{
	int len;
	char tmp_buff[20];
	
	while (HX_isspace(*str_datetime))
		++str_datetime;
	gx_strlcpy(tmp_buff, str_datetime, std::size(tmp_buff));
	HX_strrtrim(tmp_buff);
	len = strlen(tmp_buff);
	if ('Z' == tmp_buff[len - 1]) {
		pitime->type = ICT_UTC;
		len --;
		tmp_buff[len] = '\0';
	} else {
		pitime->type = ICT_FLOAT;
	}
	if (15 == len) {
		if (sscanf(tmp_buff, "%04d%02d%02dT%02d%02d%02d",
		    &pitime->year, &pitime->month, &pitime->day,
		    &pitime->hour, &pitime->minute, &pitime->second) != 6)
			return false;
		pitime->leap_second = 0;
		return true;
	} else if (17 == len) {
		return sscanf(tmp_buff, "%04d%02d%02dT%02d%02d%02d%02d",
		    &pitime->year, &pitime->month, &pitime->day,
		    &pitime->hour, &pitime->minute, &pitime->second,
		    &pitime->leap_second) == 7;
	}
	mlog(LV_DEBUG, "W-1200: Unparsable datetime: \"%s\"", tmp_buff);
	return false;
}

int ical_time::twcompare(const ical_time &o) const
{
	auto r = three_way_compare(year, o.year);
	if (r != 0)
		return r;
	r = three_way_compare(month, o.month);
	if (r != 0)
		return r;
	r = three_way_compare(day, o.day);
	if (r != 0)
		return r;
	r = three_way_compare(hour, o.hour);
	if (r != 0)
		return r;
	r = three_way_compare(minute, o.minute);
	if (r != 0)
		return r;
	r = three_way_compare(second, o.second);
	if (r != 0)
		return r;
	if (leap_second > 59 && o.leap_second <= 59)
		return 1;
	if (leap_second <= 59 && o.leap_second > 59)
		return -1;
	return 0;
}

static bool ical_is_leap_year(unsigned int year)
{
	return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

unsigned int ical_get_dayofweek(unsigned int year, unsigned int month,
    unsigned int day)
{
	return (day += month < 3 ? year -- : year - 2, 23*month/9
			+ day + 4 + year/4 - year/100 + year/400) % 7; 	
}

unsigned int ical_get_dayofyear(unsigned int year, unsigned int month,
    unsigned int day)
{
	static const int days[2][12] = {
		{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334},
		{0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335}};
	return days[ical_is_leap_year(year)][month-1] + day;
}

unsigned int ical_get_monthdays(unsigned int year, unsigned int month)
{
	static const int days[2][12] = {
		{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
		{31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}};
	if (month < 1 || month > 12) {
		mlog(LV_ERR, "E-2051: invalid parameter given to ical_get_monthdays (%u)", month);
		return 0;
	}
	return days[ical_is_leap_year(year)][month-1];
}

int ical_get_monthweekorder(int day)
{	
	return (day - 1)/7 + 1;
}

static int ical_get_negative_monthweekorder(int year, int month, int day)
{
	return (day - static_cast<int>(ical_get_monthdays(year, month))) / 7 - 1;
}

static int ical_get_yearweekorder(int year, int month, int day)
{
	return (ical_get_dayofyear(year, month, day) - 1)/7 + 1;
}

static int ical_get_negative_yearweekorder(int year, int month, int day)
{
	int yearday;
	int yeardays = 365 + ical_is_leap_year(year);
	yearday = ical_get_dayofyear(year, month, day);
	return (yearday - yeardays)/7 - 1;
}

int ical_get_dayofmonth(int year, int month, int order, int dayofweek)
{
	int day;
	int tmp_dow;
	int monthdays;
	
	if (order > 0) {
		tmp_dow = ical_get_dayofweek(year, month, 1);
		if (dayofweek >= tmp_dow)
			day = 7*(order - 1) + 1 + dayofweek - tmp_dow;
		else
			day = 7*order + 1 + dayofweek - tmp_dow;
	} else {
		monthdays = ical_get_monthdays(year, month);
		tmp_dow = ical_get_dayofweek(year, month, monthdays);
		if (tmp_dow >= dayofweek)
			day = monthdays - tmp_dow + 7*(order + 1) + dayofweek;
		else
			day = monthdays - tmp_dow + 7*order + dayofweek;
	}
	return day;
}

void ical_get_itime_from_yearday(int year, int yearday, ical_time *pitime)
{
	static const int days[2][13] = {
		{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365},
		{0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366}};
	
	pitime->year = year;
	if (ical_is_leap_year(year)) {
		for (pitime->month=1; pitime->month<=12; pitime->month++) {
			if (yearday <= days[1][pitime->month]) {
				pitime->day = yearday - days[1][pitime->month - 1];
				return;
			}
		}
		return;
	}
	for (pitime->month=1; pitime->month<=12; pitime->month++) {
		if (yearday <= days[0][pitime->month]) {
			pitime->day = yearday - days[0][pitime->month - 1];
			return;
		}
	}
}

static unsigned int ical_get_yearweeks(unsigned int year)
{
	auto dayofweek = ical_get_dayofweek(year, 1, 1);
	/*
	 * DOW    CW     YEARTYPE        DOW    CW     #WKS
	 * JAN01  JAN01  (EXAMPLE)       DEC31  DEC31  INYEAR
	 * mo     01     regular (2001)  mo     53/01  52
	 * mo     01     leap    (2024)  tu     53/01  52
	 * tu     01     regular (2002)  tu     53/01  52
	 * tu     01     leap    (2008)  we     53/01  52
	 * we     01     regular (2003)  we     53/01  52
	 * we     01     leap    (2020)  th     53/00  53
	 * th     01     regular (2009)  th     53/00  53
	 * th     01     leap    (2004)  fr     53/00  53
	 * fr     00     regular (2010)  fr     52/00  52
	 * fr     00     leap    (2016)  sa     52/00  52
	 * sa     00     regular (2005)  sa     52/00  52
	 * sa     00     leap    (2028)  su     52     52
	 * su     00     regular (2006)  su     52     52
	 * su     00     leap    (2012)  mo     53/01  52
	 */
	return dayofweek == 4 || (dayofweek == 3 && ical_is_leap_year(year)) ? 53 : 52;
}

static int ical_get_weekofyear(int year, int month,
	int day, int weekstart, BOOL *pb_yeargap)
{
	int dayofweek;
	unsigned int weeknumber;
	
	*pb_yeargap = FALSE;
	dayofweek = ical_get_dayofweek(year, month, day) - weekstart + 1;
	if (dayofweek <= 0)
		dayofweek += 7;
	weeknumber = (ical_get_dayofyear(year, month, day) - dayofweek + 10)/7;
	if (weeknumber < 1) {
		*pb_yeargap = TRUE;
		weeknumber = ical_get_yearweeks(year - 1);
	} else if (weeknumber > ical_get_yearweeks(year)) {
		*pb_yeargap = TRUE;
		weeknumber = 1;
	}
	return weeknumber;
}

static int ical_get_negative_weekofyear(int year, int month,
	int day, int weekstart, BOOL *pb_yeargap)
{
	*pb_yeargap = FALSE;
	auto dayofweek = ical_get_dayofweek(year, month, day) - weekstart + 1;
	if (dayofweek <= 0)
		dayofweek += 7;
	auto weeknumber = (ical_get_dayofyear(year, month, day) - dayofweek + 10)/7;
	auto yearweeks = ical_get_yearweeks(year);
	if (weeknumber < 1) {
		*pb_yeargap = TRUE;
		return -1;
	} else if (weeknumber > ical_get_yearweeks(year)) {
		*pb_yeargap = TRUE;
		return -ical_get_yearweeks(year + 1);
	}
	return weeknumber - yearweeks - 1;
}

void ical_time::add_year(int years)
{
	auto pitime = this;
	pitime->year += years;
	if (years % 4 == 0)
		return;
	if (pitime->month == 2 && pitime->day == 29)
		pitime->day = 28;
}

void ical_time::add_month(int months)
{
	auto pitime = this;
	int monthdays;
	
	pitime->year += months/12;
	pitime->month += months%12;
	if (pitime->month > 12) {
		pitime->year ++;
		pitime->month -= 12;
	}
	monthdays = ical_get_monthdays(pitime->year, pitime->month);
	if (pitime->day > monthdays)
		pitime->day = monthdays;
}

void ical_time::add_day(int days)
{
	int yearday = ical_get_dayofyear(year, month, day);
	auto pitime = this;
	yearday += days;
	while (true) {
		auto z = 365 + ical_is_leap_year(pitime->year);
		if (yearday <= z)
			break;
		pitime->year++;
		pitime->month = 1;
		pitime->day = 1;
		yearday -= z;
	}
	ical_get_itime_from_yearday(pitime->year, yearday, pitime);
}

void ical_time::subtract_day(int days)
{
	int yearday = ical_get_dayofyear(year, month, day);
	auto pitime = this;
	while (yearday <= days) {
		days -= yearday;
		pitime->year --;
		pitime->month = 12;
		pitime->day = 31;
		yearday = 365 + ical_is_leap_year(pitime->year);
	}
	yearday -= days;
	ical_get_itime_from_yearday(pitime->year, yearday, pitime);
}

int ical_time::delta_day(ical_time itime2) const
{
	const ical_time &itime1 = *this;
	int yearday;
	int monthdays;
	int delta_days;

	if (month < 1 || month > 12 || day < 1 || day > 31) {
		mlog(LV_ERR, "E-2052: illegal parameters to ical_time::delta_day (%u,%u)", month, day);
		return 0;
	}
	if (itime1 < itime2)
		return itime2.delta_day(itime1);
	delta_days = 0;
	while (itime2.year < itime1.year) {
		yearday = ical_get_dayofyear(itime2.year, itime2.month, itime2.day); 
		delta_days += 365 + ical_is_leap_year(itime2.year) + 1 - yearday;
		itime2.year ++;
		itime2.month = 1;
		itime2.day = 1;
	}
	while (itime2.month < itime1.month) {
		monthdays = ical_get_monthdays(itime2.year, itime2.month);
		delta_days += monthdays + 1 - itime2.day;
		itime2.month ++;
		itime2.day = 1;
	}
	delta_days += itime1.day - itime2.day;
	return delta_days;
}

void ical_time::add_hour(int hours)
{
	auto pitime = this;
	if (hours > 23)
		add_day(hours / 24);
	pitime->hour += hours%24;
	if (pitime->hour > 23) {
		add_day(1);
		pitime->hour -= 24;
	}
}

void ical_time::add_minute(int minutes)
{
	auto pitime = this;
	if (minutes > 59)
		add_hour(minutes / 60);
	pitime->minute += minutes%60;
	if (pitime->minute > 59) {
		add_hour(1);
		pitime->minute -= 60;
	}
}

void ical_time::add_second(int seconds)
{
	auto pitime = this;
	if (seconds > 59)
		add_minute(seconds / 60);
	pitime->second += seconds%60;
	if (pitime->second > 59) {
		add_minute(1);
		pitime->second -= 60;
	}
}

int weekday_to_int(const char *s)
{
	if (strcasecmp(s, "SU") == 0) return 0;
	if (strcasecmp(s, "MO") == 0) return 1;
	if (strcasecmp(s, "TU") == 0) return 2;
	if (strcasecmp(s, "WE") == 0) return 3;
	if (strcasecmp(s, "TH") == 0) return 4;
	if (strcasecmp(s, "FR") == 0) return 5;
	if (strcasecmp(s, "SA") == 0) return 6;
	return -1;
}

const char *weekday_to_str(unsigned int n)
{
	switch (n) {
	case 7:
	case 0: return "SU";
	case 1: return "MO";
	case 2: return "TU";
	case 3: return "WE";
	case 4: return "TH";
	case 5: return "FR";
	case 6: return "SA";
	default: return nullptr;
	}
}

bool ical_parse_byday(const char *pbegin, int *pdayofweek, int *pweekorder)
{
	while (HX_isspace(*pbegin))
		++pbegin;
	bool b_negative = *pbegin == '-';
	if (b_negative)
		++pbegin;
	else if (*pbegin == '+')
		++pbegin;
	*pweekorder = 0;
	if (HX_isdigit(*pbegin)) {
		char tmp_num[3]{};
		tmp_num[0] = *pbegin++;
		if (HX_isdigit(*pbegin))
			tmp_num[1] = *pbegin++;
		*pweekorder = strtol(tmp_num, nullptr, 0);
		if (*pweekorder < 1 || *pweekorder > 53)
			return false;
		if (b_negative)
			*pweekorder *= -1;
	}
	auto dow = weekday_to_int(pbegin);
	if (dow < 0)
		return false;
	*pdayofweek = dow;
	return true;
}

bool ical_parse_duration(const char *ptoken, long *pseconds)
{
	char tmp_buff[128];
	
	while (HX_isspace(*ptoken))
		++ptoken;
	int factor = 1;
	if ('+' == *ptoken) {
		ptoken ++;
	} else if ('-' == *ptoken) {
		factor = -1;
		ptoken ++;
	}
	if (*ptoken != 'P')
		return false;
	ptoken ++;

	bool b_time = false;
	int week = -1, day = -1, hour = -1, minute = -1, second = -1;
	gx_strlcpy(tmp_buff, ptoken, std::size(tmp_buff));
	ptoken = tmp_buff;
	for (char *ptoken1 = tmp_buff; *ptoken1 != '\0'; ++ptoken1) {
		switch (*ptoken1) {
		case 'W':
			if (ptoken1 == ptoken || week != -1 || b_time)
				return false;
			*ptoken1 = '\0';
			week = strtol(ptoken, nullptr, 0);
			ptoken = ptoken1 + 1;
			break;
		case 'D':
			if (ptoken1 == ptoken || day != -1 || b_time)
				return false;
			*ptoken1 = '\0';
			day = strtol(ptoken, nullptr, 0);
			ptoken = ptoken1 + 1;
			break;
		case 'T':
			if (ptoken != ptoken1 || b_time)
				return false;
			b_time = TRUE;
			ptoken = ptoken1 + 1;
			break;
		case 'H':
			if (ptoken1 == ptoken || hour != -1 || !b_time)
				return false;
			*ptoken1 = '\0';
			hour = strtol(ptoken, nullptr, 0);
			ptoken = ptoken1 + 1;
			break;
		case 'M':
			if (ptoken1 == ptoken || minute != -1 || !b_time)
				return false;
			*ptoken1 = '\0';
			minute = strtol(ptoken, nullptr, 0);
			ptoken = ptoken1 + 1;
			break;
		case 'S':
			if (ptoken1 == ptoken || second != -1 || !b_time)
				return false;
			*ptoken1 = '\0';
			second = strtol(ptoken, nullptr, 0);
			ptoken = ptoken1 + 1;
			break;
		default:
			if (!HX_isdigit(*ptoken1))
				return false;
			break;
		}
	}
	*pseconds = 0;
	if (week != -1)
		*pseconds += 7*24*60*60*week;
	if (day != -1)
		*pseconds += 24*60*60*day;
	if (hour != -1)
		*pseconds += 60*60*hour;
	if (minute != -1)
		*pseconds += 60*minute;
	if (second != -1)
		*pseconds += second;
	*pseconds *= factor;
	return true;
}

static const char *ical_get_datetime_offset(const ical_component &ptz_component,
    ical_time itime)
{
	int hour;
	int month;
	int minute;
	int second;
	int weekorder;
	int dayofweek;
	int dayofmonth;
	time_t tmp_time;
	BOOL b_standard;
	BOOL b_daylight;
	struct tm tmp_tm;
	const char *pvalue;
	const char *pvalue1;
	const char *pvalue2;
	ical_time itime_standard, itime_daylight;
	const char *standard_offset = nullptr, *daylight_offset = nullptr;
	
	b_standard = FALSE;
	b_daylight = FALSE;
	for (const auto &comp : ptz_component.component_list) {
		auto pcomponent = &comp;
		if (strcasecmp(pcomponent->m_name.c_str(), "STANDARD") != 0 &&
		    strcasecmp(pcomponent->m_name.c_str(), "DAYLIGHT") != 0)
			return NULL;
		auto piline = pcomponent->get_line("DTSTART");
		if (piline == nullptr)
			return NULL;
		if (piline->get_first_paramval("TZID") != nullptr)
			return NULL;
		pvalue = piline->get_first_subvalue();
		if (pvalue == nullptr)
			return NULL;
		ical_time itime1{}, itime2{};
		if (!ical_parse_datetime(pvalue, &itime1) || itime1.type == ICT_UTC)
			return NULL;
		if (itime < itime1)
			continue;
		piline = pcomponent->get_line("RRULE");
		if (piline == nullptr)
			goto FOUND_COMPONENT;
		pvalue = piline->get_first_subvalue_by_name("UNTIL");
		if (pvalue == nullptr)
			goto FOUND_COMPONENT;
		if (!ical_parse_datetime(pvalue, &itime2)) {
			itime2.hour = 0;
			itime2.minute = 0;
			itime2.second = 0;
			itime2.leap_second = 0;
			if (!ical_parse_date(pvalue, &itime2))
				return nullptr;
		} else {
			if (!ical_datetime_to_utc(nullptr, pvalue, &tmp_time))
				return nullptr;
			piline = pcomponent->get_line("TZOFFSETTO");
			if (piline == nullptr)
				return NULL;
			pvalue = piline->get_first_subvalue();
			if (pvalue == nullptr)
				return NULL;
			if (!ical_parse_utc_offset(pvalue, &hour, &minute))
				return nullptr;
			tmp_time -= 60*60*hour + 60*minute;
			if (gmtime_r(&tmp_time, &tmp_tm) == nullptr)
				return nullptr;
			itime2.year = tmp_tm.tm_year + 1900;
			itime2.month = tmp_tm.tm_mon + 1;
			itime2.day = tmp_tm.tm_mday;
			itime2.hour = tmp_tm.tm_hour;
			itime2.minute = tmp_tm.tm_min;
			itime2.second = tmp_tm.tm_sec;
			itime2.leap_second = 0;
		}
		if (itime > itime2)
			continue;
 FOUND_COMPONENT:
		piline = pcomponent->get_line("TZOFFSETTO");
		if (piline == nullptr)
			return NULL;
		pvalue = piline->get_first_subvalue();
		if (pvalue == nullptr)
			return NULL;
		if (strcasecmp(pcomponent->m_name.c_str(), "STANDARD") == 0) {
			b_standard = TRUE;
			standard_offset = pvalue;
			itime_standard = itime1;
		} else {
			b_daylight = TRUE;
			daylight_offset = pvalue;
			itime_daylight = itime1;
		}
		piline = pcomponent->get_line("RRULE");
		if (NULL != piline) {
			pvalue = piline->get_first_subvalue_by_name("FREQ");
			if (pvalue == nullptr || strcasecmp(pvalue, "YEARLY") != 0)
				return NULL;
			pvalue = piline->get_first_subvalue_by_name("BYDAY");
			pvalue1 = piline->get_first_subvalue_by_name("BYMONTHDAY");
			if ((pvalue == nullptr && pvalue1 == nullptr) ||
			    (pvalue != nullptr && pvalue1 != nullptr))
				return NULL;
			pvalue2 = piline->get_first_subvalue_by_name("BYMONTH");
			if (NULL == pvalue2) {
				month = itime1.month;
			} else {
				month = strtol(pvalue2, nullptr, 0);
				if (month < 1 || month > 12)
					return NULL;
			}
			if (strcasecmp(pcomponent->m_name.c_str(), "STANDARD") == 0) {
				itime_standard.year = itime.year;
				itime_standard.month = month;
			} else {
				itime_daylight.year = itime.year;
				itime_daylight.month = month;
			}
			if (NULL != pvalue) {
				if (!ical_parse_byday(pvalue, &dayofweek, &weekorder))
					return NULL;
				if (weekorder > 5 || weekorder < -5 || 0 == weekorder)
					return NULL;
				dayofmonth = ical_get_dayofmonth(itime.year,
				             itime.month, weekorder, dayofweek);
			} else {
				dayofmonth = strtol(pvalue1, nullptr, 0);
				if (abs(dayofmonth) < 1 || abs(dayofmonth) > 31)
					return NULL;
				if (dayofmonth < 0)
					dayofmonth += ical_get_monthdays(itime.year, month) + 1;
				if (dayofmonth <= 0)
					return NULL;
			}
			pvalue = piline->get_first_subvalue_by_name("BYHOUR");
			if (NULL == pvalue) {
				hour = itime1.hour;
			} else {
				hour = strtol(pvalue, nullptr, 0);
				if (hour < 0 || hour > 23)
					return NULL;
			}
			pvalue = piline->get_first_subvalue_by_name("BYMINUTE");
			if (NULL == pvalue) {
				minute = itime1.minute;
			} else {
				minute = strtol(pvalue, nullptr, 0);
				if (minute < 0 || minute > 59)
					return NULL;
			}
			pvalue = piline->get_first_subvalue_by_name("BYSECOND");
			if (NULL == pvalue) {
				second = itime1.second;
			} else {
				second = strtol(pvalue, nullptr, 0);
				if (second < 0 || second > 59)
					return NULL;
			}
			if (strcasecmp(pcomponent->m_name.c_str(), "STANDARD") == 0) {
				itime_standard.day = dayofmonth;
				itime_standard.hour = hour;
				itime_standard.minute = minute;
				itime_standard.second = second;
				itime_standard.leap_second = 0;
			} else {
				itime_daylight.day = dayofmonth;
				itime_daylight.hour = hour;
				itime_daylight.minute = minute;
				itime_daylight.second = second;
				itime_daylight.leap_second = 0;
			}
		} else {
			if (strcasecmp(pcomponent->m_name.c_str(), "STANDARD") == 0)
				itime_standard.year = itime.year;
			else
				itime_daylight.year = itime.year;
		}
	}
	if (!b_standard && !b_daylight)
		return NULL;
	if (b_standard && !b_daylight)
		return standard_offset;
	if (!b_standard && b_daylight)
		return daylight_offset;
	if (itime.year != itime_standard.year ||
	    itime.year != itime_daylight.year)
		return NULL;
	if (itime_standard >= itime_daylight)
		return itime < itime_daylight || itime >= itime_standard ?
		       standard_offset : daylight_offset;

	return itime < itime_standard || itime >= itime_daylight ?
	       daylight_offset : standard_offset;
}

bool ical_itime_to_utc(const ical_component *ptz_component,
    ical_time itime, time_t *ptime)
{
	int hour_offset;
	struct tm tmp_tm;
	int minute_offset;
	
	tmp_tm.tm_sec = itime.leap_second >= 60 ? itime.leap_second : itime.second;
	tmp_tm.tm_min = itime.minute;
	tmp_tm.tm_hour = itime.hour;
	tmp_tm.tm_mday = itime.day;
	tmp_tm.tm_mon = itime.month - 1;
	tmp_tm.tm_year = itime.year - 1900;
	tmp_tm.tm_wday = 0;
	tmp_tm.tm_yday = 0;
	tmp_tm.tm_isdst = 0;
	*ptime = timegm(&tmp_tm);
	if (ptz_component == nullptr)
		return true;
	/*
	 * @itime is anchored to @ptz_component. Conversion to tmp_tm did not
	 * change that. Because timegm() assumes @tmp_tm was UTC, @*ptime
	 * now has bias which needs to be corrected.
	 */
	//assert(itime.type != ICT_UTC);
	auto str_offset = ical_get_datetime_offset(*ptz_component, itime);
	if (str_offset == nullptr)
		return false;
	if (!ical_parse_utc_offset(str_offset, &hour_offset, &minute_offset))
		return false;
	*ptime += 60*60*hour_offset + 60*minute_offset;
	return true;
}

bool ical_datetime_to_utc(const ical_component *ptz_component,
	const char *str_datetime, time_t *ptime)
{
	ical_time itime{};
	struct tm tmp_tm;
	
	if (!ical_parse_datetime(str_datetime, &itime))
		return false;
	tmp_tm.tm_sec = itime.leap_second >= 60 ? itime.leap_second : itime.second;
	if (itime.type != ICT_UTC)
		return ical_itime_to_utc(ptz_component, itime, ptime);
	tmp_tm.tm_min = itime.minute;
	tmp_tm.tm_hour = itime.hour;
	tmp_tm.tm_mday = itime.day;
	tmp_tm.tm_mon = itime.month - 1;
	tmp_tm.tm_year = itime.year - 1900;
	tmp_tm.tm_wday = 0;
	tmp_tm.tm_yday = 0;
	tmp_tm.tm_isdst = 0;
	*ptime = timegm(&tmp_tm);
	return true;
}

bool ical_utc_to_datetime(const ical_component *ptz_component,
    time_t utc_time, ical_time *pitime)
{
	int hour;
	int minute;
	time_t tmp_time;
	struct tm tmp_tm;
	const char *pvalue;
	
	if (NULL == ptz_component) {
		/* UTC time */
		if (gmtime_r(&utc_time, &tmp_tm) == nullptr)
			return false;
		pitime->year = tmp_tm.tm_year + 1900;
		pitime->month = tmp_tm.tm_mon + 1;
		pitime->day = tmp_tm.tm_mday;
		pitime->hour = tmp_tm.tm_hour;
		pitime->minute = tmp_tm.tm_min;
		pitime->second = tmp_tm.tm_sec;
		pitime->leap_second = 0;
		pitime->type = ICT_UTC;
		return true;
	}
	pitime->type = ICT_FLOAT;
	for (const auto &comp : ptz_component->component_list) {
		auto pcomponent = &comp;
		if (strcasecmp(pcomponent->m_name.c_str(), "STANDARD") != 0 &&
		    strcasecmp(pcomponent->m_name.c_str(), "DAYLIGHT") != 0)
			return false;
		auto piline = pcomponent->get_line("TZOFFSETTO");
		if (piline == nullptr)
			return false;
		pvalue = piline->get_first_subvalue();
		if (pvalue == nullptr)
			return false;
		if (!ical_parse_utc_offset(pvalue, &hour, &minute))
			return false;
		tmp_time = utc_time - 60*60*hour - 60*minute;
		if (gmtime_r(&tmp_time, &tmp_tm) == nullptr)
			return false;
		pitime->year = tmp_tm.tm_year + 1900;
		pitime->month = tmp_tm.tm_mon + 1;
		pitime->day = tmp_tm.tm_mday;
		pitime->hour = tmp_tm.tm_hour;
		pitime->minute = tmp_tm.tm_min;
		pitime->second = tmp_tm.tm_sec;
		pitime->leap_second = 0;
		if (!ical_itime_to_utc(ptz_component, *pitime, &tmp_time))
			return false;
		if (tmp_time == utc_time)
			return true;
	}
	return false;
}

static bool ical_parse_until(const ical_component *ptz_component,
	const char *str_until, time_t *ptime)
{
	ical_time itime{};
	
	if (!ical_parse_datetime(str_until, &itime)) {
		if (!ical_parse_date(str_until, &itime))
			return false;
		return ical_itime_to_utc(ptz_component, itime, ptime);
	} else {
		return itime.type == ICT_UTC ?
		       ical_datetime_to_utc(nullptr, str_until, ptime) :
		       ical_itime_to_utc(ptz_component, itime, ptime);
	}
}

static bool ical_test_bitmap(unsigned char *pbitmap, unsigned int index)
{
	int bits;
	int bytes;
	unsigned char mask;
	
	bytes = index/8;
	bits = index%8;
	mask = 1 << bits;
	return pbitmap[bytes] & mask;
}

static void ical_set_bitmap(unsigned char *pbitmap, unsigned int index)
{
	int bits;
	int bytes;
	unsigned char mask;
	
	bytes = index/8;
	bits = index%8;
	mask = 1 << bits;
	pbitmap[bytes] |= mask;
}

static rrule_by ical_test_rrule(ical_rrule *pirrule, ical_time itime)
{
	int yearday;
	int yeardays;
	int dayofweek;
	int weekorder;
	int nweekorder;
	BOOL b_yeargap;
	
	if (pirrule->test_bymask(rrule_by::month))
		if (!ical_test_bitmap(pirrule->month_bitmap, itime.month - 1))
			return rrule_by::month;
	if (pirrule->test_bymask(rrule_by::weekno)) {
		weekorder = ical_get_weekofyear(itime.year, itime.month,
					itime.day, pirrule->weekstart, &b_yeargap);
		if (b_yeargap && pirrule->frequency == ical_frequency::year)
			return rrule_by::weekno;
		nweekorder = ical_get_negative_weekofyear(itime.year, itime.month,
		             itime.day, pirrule->weekstart, &b_yeargap);
		if (b_yeargap && pirrule->frequency == ical_frequency::year)
			return rrule_by::weekno;
		if (!ical_test_bitmap(pirrule->week_bitmap, weekorder - 1) &&
		    !ical_test_bitmap(pirrule->nweek_bitmap, -nweekorder - 1))
			return rrule_by::weekno;
	}
	if (pirrule->test_bymask(rrule_by::yearday)) {
		yeardays = 365 + ical_is_leap_year(itime.year);
		yearday = ical_get_dayofyear(itime.year, itime.month, itime.day);
		if (!ical_test_bitmap(pirrule->yday_bitmap, yearday - 1) &&
		    !ical_test_bitmap(pirrule->nyday_bitmap, yeardays - yearday))
			return rrule_by::yearday;
	}
	if (pirrule->test_bymask(rrule_by::monthday))
		if (!ical_test_bitmap(pirrule->mday_bitmap, itime.day - 1) &&
		    !ical_test_bitmap(pirrule->nmday_bitmap,
		    ical_get_monthdays(itime.year, itime.month) - itime.day))
			return rrule_by::monthday;
	if (pirrule->test_bymask(rrule_by::day)) {
		dayofweek = ical_get_dayofweek(itime.year, itime.month, itime.day);
		if (ical_frequency::week == pirrule->frequency) {
			weekorder = itime.delta_day(pirrule->base_itime) / 7 + 1;
			nweekorder = -(itime.delta_day(pirrule->next_base_itime) - 1) / 7 - 1;
		} else if (pirrule->frequency == ical_frequency::month ||
		    pirrule->test_bymask(rrule_by::month)) {
			weekorder = ical_get_monthweekorder(itime.day);
			nweekorder = ical_get_negative_monthweekorder(itime.year,
			             itime.month, itime.day);
		} else {
			weekorder  = ical_get_yearweekorder(itime.year,
			             itime.month, itime.day);
			nweekorder = ical_get_negative_yearweekorder(itime.year,
			             itime.month, itime.day);
		}
		if (!ical_test_bitmap(pirrule->wday_bitmap, 7 * (weekorder - 1) + dayofweek) &&
		    !ical_test_bitmap(pirrule->nwday_bitmap, 7 * (-nweekorder - 1) + dayofweek))
			return rrule_by::day;
	}
	if (pirrule->test_bymask(rrule_by::hour))
		if (!ical_test_bitmap(pirrule->hour_bitmap, itime.hour))
			return rrule_by::hour;
	if (pirrule->test_bymask(rrule_by::minute))
		if (!ical_test_bitmap(pirrule->minute_bitmap, itime.minute))
			return rrule_by::minute;
	if (pirrule->test_bymask(rrule_by::second))
		if (!ical_test_bitmap(pirrule->second_bitmap, itime.second))
			return rrule_by::second;
	return rrule_by::setpos;
}

static bool ical_test_setpos(ical_rrule *pirrule)
{
	if (!ical_test_bitmap(pirrule->setpos_bitmap, pirrule->cur_setpos - 1) &&
	    !ical_test_bitmap(pirrule->nsetpos_bitmap, pirrule->setpos_count - pirrule->cur_setpos))
		return false;
	return true;
}

static ical_time ical_next_rrule_itime(ical_rrule *pirrule,
    rrule_by hint_result, ical_time itime)
{
	int dayofweek;
	
	if (hint_result == rrule_by::setpos) {
		auto req = pirrule->real_frequency == pirrule->frequency;
		switch (pirrule->real_frequency) {
		case ical_frequency::year:
			itime.add_year(pirrule->interval);
			break;
		case ical_frequency::month:
			itime.add_month(req ? pirrule->interval : 1);
			break;
		case ical_frequency::week:
			itime.add_day(req ? 7 * pirrule->interval : 7);
			break;
		case ical_frequency::day:
			itime.add_day(req ? pirrule->interval : 1);
			break;
		case ical_frequency::hour:
			itime.add_hour(req ? pirrule->interval : 1);
			break;
		case ical_frequency::minute:
			itime.add_minute(req ? pirrule->interval : 1);
			break;
		case ical_frequency::second:
			itime.add_second(req ? pirrule->interval : 1);
			break;
		default:
			assert(false);
			break;
		}
		return itime;
	}
	switch (pirrule->frequency) {
	case ical_frequency::year:
	case ical_frequency::month:
		switch (hint_result) {
		case rrule_by::month:
			dayofweek = ical_get_dayofweek(itime.year, itime.month, itime.day);
			itime.add_month(1);
			if (pirrule->test_bymask(rrule_by::weekno))
				itime.day = ical_get_dayofmonth(itime.year,
				            itime.month, 1, dayofweek);
			if (pirrule->test_bymask(rrule_by::yearday) ||
			    pirrule->test_bymask(rrule_by::monthday) ||
			    pirrule->test_bymask(rrule_by::day))
				itime.day = 1;
			if (pirrule->test_bymask(rrule_by::hour))
				itime.hour = 0;
			if (pirrule->test_bymask(rrule_by::minute))
				itime.minute = 0;
			if (pirrule->test_bymask(rrule_by::second))
				itime.second = 0;
			break;
		case rrule_by::weekno:
			itime.add_day(7);
			if (pirrule->test_bymask(rrule_by::yearday) ||
			    pirrule->test_bymask(rrule_by::monthday) ||
			    pirrule->test_bymask(rrule_by::day)) {
				dayofweek = ical_get_dayofweek(itime.year, itime.month, itime.day);
				if (dayofweek >= pirrule->weekstart)
					itime.subtract_day(dayofweek - pirrule->weekstart);
				else
					itime.subtract_day(7 + dayofweek - pirrule->weekstart);
			}
			if (pirrule->test_bymask(rrule_by::hour))
				itime.hour = 0;
			if (pirrule->test_bymask(rrule_by::minute))
				itime.minute = 0;
			if (pirrule->test_bymask(rrule_by::second))
				itime.second = 0;
			break;
		case rrule_by::yearday:
		case rrule_by::monthday:
		case rrule_by::day:
			itime.add_day(1);
			if (pirrule->test_bymask(rrule_by::hour))
				itime.hour = 0;
			if (pirrule->test_bymask(rrule_by::minute))
				itime.minute = 0;
			if (pirrule->test_bymask(rrule_by::second))
				itime.second = 0;
			break;
		case rrule_by::hour:
			itime.add_hour(1);
			if (pirrule->test_bymask(rrule_by::minute))
				itime.minute = 0;
			if (pirrule->test_bymask(rrule_by::second))
				itime.second = 0;
			break;
		case rrule_by::minute:
			itime.add_minute(1);
			if (pirrule->test_bymask(rrule_by::second))
				itime.second = 0;
			break;
		case rrule_by::second:
			itime.add_second(1);
			break;
		default:
			break;
		}
		break;
	case ical_frequency::week:
		switch (hint_result) {
		case rrule_by::yearday:
		case rrule_by::monthday:
		case rrule_by::day:
			itime.add_day(1);
			break;
		case rrule_by::hour:
			itime.add_hour(1);
			break;
		case rrule_by::minute:
			itime.add_minute(1);
			break;
		case rrule_by::second:
			itime.add_second(1);
			break;
		default:
			itime.add_day(7);
			break;
		}
		break;
	case ical_frequency::day:
		switch (hint_result) {
		case rrule_by::hour:
			itime.add_hour(1);
			break;
		case rrule_by::minute:
			itime.add_minute(1);
			break;
		case rrule_by::second:
			itime.add_second(1);
			break;
		default:
			itime.add_day(1);
			break;
		}
		break;
	case ical_frequency::hour:
		switch (hint_result) {
		case rrule_by::minute:
			itime.add_minute(1);
			break;
		case rrule_by::second:
			itime.add_second(1);
			break;
		default:
			itime.add_hour(1);
			break;
		}
		break;
	case ical_frequency::minute:
		switch (hint_result) {
		case rrule_by::second:
			itime.add_second(1);
			break;
		default:
			itime.add_minute(1);
			break;
		}
		break;
	case ical_frequency::second:
		itime.add_second(1);
		break;
	default:
		assert(false);
		break;
	}
	switch (pirrule->frequency) {
	case ical_frequency::year:
		if (itime.year > pirrule->base_itime.year)
			itime = pirrule->next_base_itime;
		break;
	case ical_frequency::month:
		if (itime.month > pirrule->base_itime.month)
			itime = pirrule->next_base_itime;
		break;
	case ical_frequency::week:
		if (itime.delta_day(pirrule->base_itime) >= 7)
			itime = pirrule->next_base_itime;
		break;
	case ical_frequency::day:
		if (itime.day > pirrule->base_itime.day)
			itime = pirrule->next_base_itime;
		break;
	case ical_frequency::hour:
		if (itime.hour > pirrule->base_itime.hour)
			itime = pirrule->next_base_itime;
		break;
	case ical_frequency::minute:
		if (itime.minute > pirrule->base_itime.minute)
			itime = pirrule->next_base_itime;
		break;
	case ical_frequency::second:
		if (itime.second > pirrule->base_itime.second)
			itime = pirrule->next_base_itime;
		break;
	default:
		assert(false);
		return {};
	}
	return itime;
}
	
static void ical_calculate_setpos(ical_rrule *pirrule)
{
	ical_time itime;
	
	pirrule->cur_setpos = 0;
	pirrule->setpos_count = 0;
	itime = pirrule->base_itime;
	for (rrule_by hint_result = rrule_by::setpos;
	    pirrule->next_base_itime > itime;
	    itime = ical_next_rrule_itime(pirrule, hint_result, itime)) {
		hint_result = ical_test_rrule(pirrule, itime);
		if (hint_result == rrule_by::setpos)
			pirrule->setpos_count ++;
	}
}

static void ical_next_rrule_base_itime(ical_rrule *pirrule)
{
	pirrule->next_base_itime = pirrule->base_itime;
	switch (pirrule->frequency) {
	case ical_frequency::year:
		pirrule->next_base_itime.add_year(pirrule->interval);
		break;
	case ical_frequency::month:
		pirrule->next_base_itime.add_month(pirrule->interval);
		break;
	case ical_frequency::week:
		pirrule->next_base_itime.add_day(7 * pirrule->interval);
		break;
	case ical_frequency::day:
		pirrule->next_base_itime.add_day(pirrule->interval);
		break;
	case ical_frequency::hour:
		pirrule->next_base_itime.add_hour(pirrule->interval);
		break;
	case ical_frequency::minute:
		pirrule->next_base_itime.add_minute(pirrule->interval);
		break;
	case ical_frequency::second:
		pirrule->next_base_itime.add_second(pirrule->interval);
		break;
	default:
		assert(false);
		return;
	}
}

static enum ical_frequency parse_freq(const char *s)
{
	if (s == nullptr)                        return ical_frequency::invalid;
	else if (strcasecmp(s, "SECONDLY") == 0) return ical_frequency::second;
	else if (strcasecmp(s, "MINUTELY") == 0) return ical_frequency::minute;
	else if (strcasecmp(s, "HOURLY") == 0)   return ical_frequency::hour;
	else if (strcasecmp(s, "DAILY") == 0)    return ical_frequency::day;
	else if (strcasecmp(s, "WEEKLY") == 0)   return ical_frequency::week;
	else if (strcasecmp(s, "MONTHLY") == 0)  return ical_frequency::month;
	else if (strcasecmp(s, "YEARLY") == 0)   return ical_frequency::year;
	else                                     return ical_frequency::invalid;
}

static long clamp_low_n(const char *s, long def)
{
	if (s == nullptr)
		return def;
	auto v = strtol(s, nullptr, 0);
	return v > 0 ? v : INT_MIN;
}

/*
 * @ptz_component: if NULL, represents UTC
 *
 * On success, returns %nullptr. On error, the error indicator string is returned.
 */
const char *ical_parse_rrule(const ical_component *ptz_component,
    time_t start_time, const std::vector<ical_value> *pvalue_list,
    ical_rrule *pirrule)
{
	*pirrule = {};
	pirrule->frequency = parse_freq(ical_get_first_subvalue_by_name_internal(pvalue_list, "FREQ"));
	if (pirrule->frequency == ical_frequency::invalid)
		return "E-2825";
	pirrule->real_frequency = pirrule->frequency;
	pirrule->interval = clamp_low_n(ical_get_first_subvalue_by_name_internal(pvalue_list, "INTERVAL"), 1);
	pirrule->total_count = clamp_low_n(ical_get_first_subvalue_by_name_internal(pvalue_list, "COUNT"), 0);
	if (pirrule->interval == INT_MIN || pirrule->total_count == INT_MIN)
		return "E-2826";

	auto pvalue = ical_get_first_subvalue_by_name_internal(pvalue_list, "UNTIL");
	if (NULL != pvalue) {
		if (pirrule->total_count != 0)
			return "E-2828: Cannot combine COUNT with UNTIL in RRULE";
		time_t until_time;
		if (!ical_parse_until(ptz_component, pvalue, &until_time))
			return "E-2829: RRULE has invalid UNTIL";
		if (until_time < start_time)
			return "E-2830: RRULE has UNTIL < DTSTART";
		/* until==start can happen with a recurrent series with one occurrence */
		pirrule->b_until = true;
		ical_utc_to_datetime(ptz_component,
			until_time, &pirrule->until_itime);
	}
	ical_utc_to_datetime(ptz_component,
		start_time, &pirrule->instance_itime);
	auto pbysecond_list = ical_get_subval_list_internal(pvalue_list, "BYSECOND");
	if (NULL != pbysecond_list) {
		for (const auto &pnv2 : *pbysecond_list) {
			long tmp_int = LONG_MIN;
			if (!pnv2.empty())
				tmp_int = strtol(pnv2.c_str(), nullptr, 0);
			if (tmp_int < 0 || tmp_int > 59)
				continue;
			ical_set_bitmap(pirrule->second_bitmap, tmp_int);
		}
		if (pirrule->real_frequency > ical_frequency::second)
			pirrule->real_frequency = ical_frequency::second;
		pirrule->set_bymask(rrule_by::second);
	}
	auto pbyminute_list = ical_get_subval_list_internal(pvalue_list, "BYMINUTE");
	if (NULL != pbyminute_list) {
		for (const auto &pnv2 : *pbyminute_list) {
			long tmp_int = LONG_MIN;
			if (!pnv2.empty())
				tmp_int = strtol(pnv2.c_str(), nullptr, 0);
			if (tmp_int < 0 || tmp_int > 59)
				continue;
			ical_set_bitmap(pirrule->minute_bitmap, tmp_int);
		}
		if (pirrule->real_frequency > ical_frequency::minute)
			pirrule->real_frequency = ical_frequency::minute;
		pirrule->set_bymask(rrule_by::minute);
	}
	auto pbyhour_list = ical_get_subval_list_internal(pvalue_list, "BYHOUR");
	if (NULL != pbyhour_list) {
		for (const auto &pnv2 : *pbyhour_list) {
			long tmp_int = LONG_MIN;
			if (!pnv2.empty())
				tmp_int = strtol(pnv2.c_str(), nullptr, 0);
			if (tmp_int < 0 || tmp_int > 23)
				continue;
			ical_set_bitmap(pirrule->hour_bitmap, tmp_int);
		}
		if (pirrule->real_frequency > ical_frequency::hour)
			pirrule->real_frequency = ical_frequency::hour;
		pirrule->set_bymask(rrule_by::hour);
	}
	auto pbymday_list = ical_get_subval_list_internal(pvalue_list, "BYMONTHDAY");
	if (NULL != pbymday_list) {
		for (const auto &pnv2 : *pbymday_list) {
			long tmp_int = LONG_MIN;
			if (!pnv2.empty())
				tmp_int = strtol(pnv2.c_str(), nullptr, 0);
			if (tmp_int < -31 || 0 == tmp_int || tmp_int > 31)
				continue;
			if (tmp_int > 0)
				ical_set_bitmap(pirrule->mday_bitmap, tmp_int - 1);
			else
				ical_set_bitmap(pirrule->nmday_bitmap, -tmp_int - 1);
		}
		if (pirrule->real_frequency > ical_frequency::day)
			pirrule->real_frequency = ical_frequency::day;
		pirrule->set_bymask(rrule_by::monthday);
	}
	auto pbyyday_list = ical_get_subval_list_internal(pvalue_list, "BYYEARDAY");
	if (NULL != pbyyday_list) {
		for (const auto &pnv2 : *pbyyday_list) {
			long tmp_int = LONG_MIN;
			if (!pnv2.empty())
				tmp_int = strtol(pnv2.c_str(), nullptr, 0);
			if (tmp_int < -366 || 0 == tmp_int || tmp_int > 366)
				continue;
			if (tmp_int > 0)
				ical_set_bitmap(pirrule->yday_bitmap, tmp_int - 1);
			else
				ical_set_bitmap(pirrule->nyday_bitmap, -tmp_int - 1);
		}
		if (pirrule->real_frequency > ical_frequency::day)
			pirrule->real_frequency = ical_frequency::day;
		pirrule->set_bymask(rrule_by::yearday);
	}
	auto pbywday_list = ical_get_subval_list_internal(pvalue_list, "BYDAY");
	if (NULL != pbywday_list) {
		if (pirrule->frequency != ical_frequency::week &&
		    pirrule->frequency != ical_frequency::month &&
		    pirrule->frequency != ical_frequency::year)
			return "E-2841: RRULE has BYDAY but is not of frequency WEEK/MONTH/YEAR";
		for (const auto &pnv2 : *pbywday_list) {
			int dayofweek = -1, weekorder = -1;
			if (!ical_parse_byday(pnv2.c_str(), &dayofweek, &weekorder))
				continue;
			if (ical_frequency::month == pirrule->frequency) {
				if (weekorder > 5 || weekorder < -5)
					return "E-2844: RRULE.FREQ=MONTHLY with invalid weekorder";
				else if (weekorder > 0)
					ical_set_bitmap(pirrule->wday_bitmap,
						7*(weekorder - 1) + dayofweek);
				else if (weekorder < 0)
					ical_set_bitmap(pirrule->nwday_bitmap,
						7 * (-weekorder - 1) + dayofweek);
				else
					for (int i = 0; i < 5; ++i)
						ical_set_bitmap(pirrule->wday_bitmap, 7*i + dayofweek); 
			} else if (ical_frequency::year == pirrule->frequency) {
				if (weekorder > 0)
					ical_set_bitmap(pirrule->wday_bitmap,
						7*(weekorder - 1) + dayofweek);
				else if (weekorder < 0)
					ical_set_bitmap(pirrule->nwday_bitmap,
						7 * (-weekorder - 1) + dayofweek);
				else
					for (int i = 0; i < 53; ++i)
						ical_set_bitmap(pirrule->wday_bitmap, 7*i + dayofweek); 
			} else {
				if (weekorder != 0)
					return "E-2845: RRULE with invalid weekorder";
				ical_set_bitmap(pirrule->wday_bitmap, dayofweek);
			}
		}
		if (pirrule->real_frequency > ical_frequency::day)
			pirrule->real_frequency = ical_frequency::day;
		pirrule->set_bymask(rrule_by::day);
	}
	auto pbywnum_list = ical_get_subval_list_internal(pvalue_list, "BYWEEKNO");
	if (NULL != pbywnum_list) {
		for (const auto &pnv2 : *pbywnum_list) {
			long tmp_int = LONG_MIN;
			if (!pnv2.empty())
				tmp_int = strtol(pnv2.c_str(), nullptr, 0);
			if (tmp_int < -53 || 0 == tmp_int || tmp_int > 53)
				continue;
			if (tmp_int > 0)
				ical_set_bitmap(pirrule->week_bitmap, tmp_int - 1);
			else
				ical_set_bitmap(pirrule->nweek_bitmap, -tmp_int - 1);
		}
		if (pirrule->real_frequency > ical_frequency::week)
			pirrule->real_frequency = ical_frequency::week;
		pirrule->set_bymask(rrule_by::weekno);
	}
	auto pbymonth_list = ical_get_subval_list_internal(pvalue_list, "BYMONTH");
	if (NULL != pbymonth_list) {
		for (const auto &pnv2 : *pbymonth_list) {
			long tmp_int = LONG_MIN;
			if (!pnv2.empty())
				tmp_int = strtol(pnv2.c_str(), nullptr, 0);
			if (tmp_int < 1 || tmp_int > 12)
				continue;
			ical_set_bitmap(pirrule->month_bitmap, tmp_int - 1);
		}
		if (pirrule->real_frequency > ical_frequency::month)
			pirrule->real_frequency = ical_frequency::month;
		pirrule->set_bymask(rrule_by::month);
	}
	auto psetpos_list = ical_get_subval_list_internal(pvalue_list, "BYSETPOS");
	if (NULL != psetpos_list) {
		switch (pirrule->frequency) {
		case ical_frequency::second:
			return "E-2850: RRULE has both BYSECOND and BYSETPOS";
		case ical_frequency::minute:
			if (pirrule->real_frequency != ical_frequency::second)
				return "E-2851";
			if (60 * pirrule->interval > 366)
				return "E-2852";
			break;
		case ical_frequency::hour:
			if (pirrule->real_frequency != ical_frequency::minute)
				return "E-2853";
			if (60 * pirrule->interval > 366)
				return "E-2854";
			break;
		case ical_frequency::day:
			if (pirrule->real_frequency != ical_frequency::hour)
				return "E-2855";
			if (24 * pirrule->interval > 366)
				return "E-2856";
			break;
		case ical_frequency::week:
			if (pirrule->real_frequency == ical_frequency::day) {
				break;
			} else if (pirrule->real_frequency == ical_frequency::hour) {
				if (7 * 24 * pirrule->interval > 366)
					return "E-2857";
				break;
			}
			return "E-2858";
		case ical_frequency::month:
			if (pirrule->real_frequency == ical_frequency::day) {
				if (31 * pirrule->interval > 366)
					return "E-2859";
			} else if (pirrule->real_frequency == ical_frequency::week) {
				if (5 * pirrule->interval > 366)
					return "E-2860";
			} else {
				return "E-2861";
			}
			break;
		case ical_frequency::year:
			if (pirrule->real_frequency == ical_frequency::day) {
				if (pirrule->interval > 1)
					return "E-2862";
			} else if (pirrule->real_frequency == ical_frequency::week) {
				if (pirrule->interval > 8)
					return "E-2863";
			} else if (pirrule->real_frequency == ical_frequency::month) {
				if (pirrule->interval > 30)
					return "E-2864";
			} else {
				return "E-2865";
			}
			break;
		default:
			assert(false);
			return "E-2824";
		}
		for (const auto &pnv2 : *psetpos_list) {
			long tmp_int = LONG_MIN;
			if (!pnv2.empty())
				tmp_int = strtol(pnv2.c_str(), nullptr, 0);
			if (tmp_int < -366 || 0 == tmp_int || tmp_int > 366)
				continue;
			if (tmp_int > 0)
				ical_set_bitmap(pirrule->setpos_bitmap, tmp_int - 1);
			else
				ical_set_bitmap(pirrule->nsetpos_bitmap, -tmp_int - 1);
		}
		pirrule->set_bymask(rrule_by::setpos);
	}
	pvalue = ical_get_first_subvalue_by_name_internal(pvalue_list, "WKST");
	if (NULL != pvalue) {
		auto dow = weekday_to_int(pvalue);
		if (dow < 0)
			return "E-2868";
		pirrule->weekstart = dow;
	} else {
		pirrule->weekstart = pbywnum_list != nullptr;
	}
	auto itime = pirrule->instance_itime;
	switch (pirrule->frequency) {
	case ical_frequency::second:
		break;
	case ical_frequency::minute:
		if (pbysecond_list != nullptr)
			itime.second = 0;
		break;
	case ical_frequency::hour:
		if (pbyminute_list != nullptr)
			itime.minute = 0;
		if (pbysecond_list != nullptr)
			itime.second = 0;
		break;
	case ical_frequency::day:
		if (pbyhour_list != nullptr)
			itime.hour = 0;
		if (pbyminute_list != nullptr)
			itime.minute = 0;
		if (pbysecond_list != nullptr)
			itime.second = 0;
		break;
	case ical_frequency::week:
		if (NULL != pbywday_list) {
			int dayofweek = ical_get_dayofweek(itime.year,
			                itime.month, itime.day);
			if (dayofweek >= pirrule->weekstart)
				itime.subtract_day(dayofweek - pirrule->weekstart);
			else
				itime.subtract_day(7 + dayofweek - pirrule->weekstart);
		}
		if (pbyhour_list != nullptr)
			itime.hour = 0;
		if (pbyminute_list != nullptr)
			itime.minute = 0;
		if (pbysecond_list != nullptr)
			itime.second = 0;
		break;
	case ical_frequency::month:
		if (pbyyday_list != nullptr || pbymday_list != nullptr ||
		    pbywday_list != nullptr)
			itime.day = 1;
		if (pbyhour_list != nullptr)
			itime.hour = 0;
		if (pbyminute_list != nullptr)
			itime.minute = 0;
		if (pbysecond_list != nullptr)
			itime.second = 0;
		break;
	case ical_frequency::year:
		if (pbymonth_list != nullptr)
			itime.month = 1;
		if (pbyyday_list != nullptr || pbymday_list != nullptr ||
		    pbywday_list != nullptr)
			itime.day = 1;
		if (pbyhour_list != nullptr)
			itime.hour = 0;
		if (pbyminute_list != nullptr)
			itime.minute = 0;
		if (pbysecond_list != nullptr)
			itime.second = 0;
		break;
	default:
		assert(false);
		return nullptr;
	}
	pirrule->base_itime = itime;
	ical_next_rrule_base_itime(pirrule);
	if (pirrule->test_bymask(rrule_by::setpos))
		ical_calculate_setpos(pirrule);
	for (rrule_by hint_result = rrule_by::setpos;
	     itime < pirrule->next_base_itime;
	     itime = ical_next_rrule_itime(pirrule, hint_result, itime)) {
		if (pirrule->b_until && itime > pirrule->until_itime)
			return "E-2869";
		hint_result = ical_test_rrule(pirrule, itime);
		if (hint_result != rrule_by::setpos)
			continue;
		if (pirrule->test_bymask(rrule_by::setpos)) {
			pirrule->cur_setpos ++;
			if (!ical_test_setpos(pirrule))
				continue;
		}
		int cmp_result = itime.twcompare(pirrule->instance_itime);
		if (cmp_result < 0) {
			continue;
		} else if (cmp_result > 0) {
			pirrule->b_start_exceptional = true;
			pirrule->real_start_itime = itime;
			pirrule->current_instance = 1;
			pirrule->next_base_itime = pirrule->base_itime;
			return nullptr;
		}
		pirrule->current_instance = 1;
		return nullptr;
	}
	auto base_itime = pirrule->base_itime;
	itime = pirrule->instance_itime;
	pirrule->current_instance = 1;
	pirrule->instance_itime = pirrule->next_base_itime;
	if (!pirrule->iterate()) {
		pirrule->total_count = 1;
		pirrule->instance_itime = itime;
	} else {
		pirrule->real_start_itime = pirrule->instance_itime;
		pirrule->next_base_itime = pirrule->base_itime;
		pirrule->base_itime = base_itime;
		pirrule->instance_itime = itime;
	}
	pirrule->current_instance = 1;
	pirrule->b_start_exceptional = true;
	return nullptr;
}

bool ical_rrule::iterate()
{
	auto pirrule = this;
	ical_time itime;
	
	if (pirrule->total_count != 0 &&
	    pirrule->current_instance >= pirrule->total_count)
		return false;
	if (pirrule->b_start_exceptional) {
		itime = pirrule->real_start_itime;
		if (pirrule->b_until && itime > pirrule->until_itime)
			return false;
		pirrule->b_start_exceptional = false;
		pirrule->current_instance ++;
		pirrule->instance_itime = itime;
		pirrule->base_itime = pirrule->next_base_itime;
		ical_next_rrule_base_itime(pirrule);
		return true;
	}
	rrule_by hint_result = rrule_by::setpos;
	itime = pirrule->instance_itime;
	while (true) {
		itime = ical_next_rrule_itime(pirrule, hint_result, itime);
		if (pirrule->b_until && itime > pirrule->until_itime)
			return false;
		if (itime.year >= SYSTEMTIME::maxyear)
			/*
			 * If we are still iterating, something is fishy. Break
			 * it up. Contemporary OSes cannot represent something
			 * this high anyway.
			 */
			return false;
		if (itime >= pirrule->next_base_itime) {
			pirrule->base_itime = pirrule->next_base_itime;
			itime = pirrule->next_base_itime;
			ical_next_rrule_base_itime(pirrule);
			if (pirrule->test_bymask(rrule_by::setpos))
				ical_calculate_setpos(pirrule);
		}
		hint_result = ical_test_rrule(pirrule, itime);
		if (hint_result != rrule_by::setpos)
			continue;
		if (pirrule->test_bymask(rrule_by::setpos)) {
			pirrule->cur_setpos++;
			if (!ical_test_setpos(pirrule))
				continue;
		}
		pirrule->current_instance++;
		pirrule->instance_itime = itime;
		return true;
	}
}
