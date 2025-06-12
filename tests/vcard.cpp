// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023 grommunio GmbH
// This file is part of Gromox.
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <utility>
#include <libHX/string.h>
#include <gromox/ical.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mime.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/vcard.hpp>
#include "../tools/staticnpmap.cpp"
#include "../tools/genimport.hpp"
#undef assert
#define assert(x) do { if (!(x)) { printf("%s failed\n", #x); return EXIT_FAILURE; } } while (false)

using namespace std::string_literals;
using namespace gromox;

namespace {
struct tzsel_init {
	tzsel_init();
	ical_component lineisl;
};
}


static constexpr char dt_head[] =
"BEGIN:VCALENDAR\n"
"PRODID:-//Google Inc//Google Calendar 70.9054//EN\n"
"VERSION:2.0\n"
"BEGIN:VTIMEZONE\n"
"TZID:Line Islands Standard Time\n"
"BEGIN:STANDARD\n"
"DTSTART:16010101T000000\n"
"TZOFFSETFROM:+1400\n"
"TZOFFSETTO:+1400\n"
"END:STANDARD\n"
"END:VTIMEZONE\n"
"CALSCALE:GREGORIAN\n"
"METHOD:REQUEST\n"
"BEGIN:VEVENT\n";

static constexpr char dt_foot[] =
"ORGANIZER;CN=source:mailto:source@googlemail.com\n"
"ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=\n"
" TRUE;CN=target@googlemail.com;X-NUM-GUESTS=0:mailto:target@googlemail.com\n"
"ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED;RSVP=TRUE\n"
" ;CN=sender;X-NUM-GUESTS=0:mailto:sender@googlemail.com\n"
"X-MICROSOFT-CDO-OWNERAPPTID:1415721622\n"
"CREATED:20231205T165627Z\n"
"DESCRIPTION:\n"
"LAST-MODIFIED:20231205T165627Z\n"
"LOCATION:\n"
"SEQUENCE:0\n"
"STATUS:CONFIRMED\n"
"TRANSP:TRANSPARENT\n"
"END:VEVENT\n"
"END:VCALENDAR\n"
;

static constexpr const char *dt_values[] = {
	":20240101T000000Z",
	";TZID=Line Islands Standard Time:20240101T000000Z",
	":20240101T000000",
	";TZID=Line Islands Standard Time:20240101T000000",
	":20240101",
	";VALUE=DATE:20240101",
	";VALUE=DATE;TZID=Line Islands Standard Time:20240101",
};

static tzsel_init tzsel;

tzsel_init::tzsel_init() : lineisl("VTIMEZONE")
{
	lineisl.append_line("TZID", "Line Islands Standard Time");
	auto &c = lineisl.append_comp("STANDARD");
	c.append_line("DTSTART", "16010101T000000");
	c.append_line("TZOFFSETFROM", "+1400");
	c.append_line("TZOFFSETTO", "+1400");
}

static int t_mime()
{
	MIME m{};
	m.mime_type = mime_type::single;
	char b[4];
	size_t bsize = sizeof(b);
	m.read_head(b, &bsize);
	return EXIT_SUCCESS;
}

static void t_card()
{
	vcard C;
	auto &l = C.append_line("ADR");
	l.append_param("TYPE", "WORK");
	vcard_value v;
	v.append_subval("HOME");
	v.append_subval("HOME2");
	l.append_value(std::move(v));
	v = {};
	v.append_subval("DO");
	v.append_subval("DO2");
	l.append_value(std::move(v));

	char buf[128000];
	if (!C.serialize(buf, std::size(buf)))
		printf("ERROR\n");
	else
		printf("%s\n", buf);
	C.clear();
	C.load_single_from_str_move(buf);
	if (!C.serialize(buf, std::size(buf)))
		printf("ERROR\n");
	else
		printf("%s\n", buf);

	gx_strlcpy(buf, "BEGIN:VCARD\n\nEND:VCARD\n", sizeof(buf));
	C.load_single_from_str_move(buf);
}

static int t_ical_api()
{
	int hour = -99, min = -99;
	assert(ical_parse_utc_offset("+0100", &hour, &min));
	assert(hour == -1 && min == 0);
	assert(ical_parse_utc_offset("-0100", &hour, &min));
	assert(hour == 1 && min == 0);
	assert(!ical_parse_utc_offset("0100", &hour, &min));
	assert(hour == 0 && min == 0);

	ical_time it;
	assert(ical_parse_datetime("20231224T123456Z", &it));
	assert(it.year == 2023 && it.month == 12 && it.day == 24 &&
	       it.hour == 12 && it.minute == 34 && it.second == 56 &&
	       it.type == ICT_UTC);
	assert(ical_parse_datetime("20101010T101010", &it));
	assert(it.year == 2010 && it.month == 10 && it.day == 10 &&
	       it.hour == 10 && it.minute == 10 && it.second == 10 &&
	       it.type == ICT_FLOAT);
	assert(!ical_parse_datetime("20231224T1234567", &it));
	assert(!ical_parse_datetime("20231224X123456", &it));
	assert(!ical_parse_datetime("20231224T12345", &it));

	assert(ical_parse_date("20211221", &it));
	assert(it.year == 2021 && it.month == 12 && it.day == 21 &&
	       it.hour == 0 && it.minute == 0 && it.second == 0 &&
	       it.type == ICT_FLOAT_DAY);
	assert(!ical_parse_date("202112211", &it));

	int dow = -99, weekord = -99;
	assert(ical_parse_byday("MO", &dow, &weekord));
	assert(weekord == 0 && dow == 1);
	assert(ical_parse_byday("-1TU", &dow, &weekord));
	assert(weekord == -1 && dow == 2);
	assert(ical_parse_byday("+2WE", &dow, &weekord));
	assert(weekord == 2 && dow == 3);
	assert(ical_parse_byday("3TH", &dow, &weekord));
	assert(weekord == 3 && dow == 4);
	assert(ical_parse_byday("5FR", &dow, &weekord));
	assert(weekord == 5 && dow == 5);
	assert(ical_parse_byday("-5SA", &dow, &weekord));
	assert(weekord == -5 && dow == 6);
	assert(ical_parse_byday("53SU", &dow, &weekord));
	assert(weekord == 53 && dow == 0);
	assert(!ical_parse_byday("54SU", &dow, &weekord));
	assert(!ical_parse_byday("SAT", &dow, &weekord));

	long sec = -1;
	assert(ical_parse_duration("PT0S", &sec));
	assert(sec == 0);
	assert(ical_parse_duration("-P9DT3H4M5S", &sec));
	assert(sec == -(86400 * 9 + 3600 * 3 + 4 * 60 + 5));
	assert(!ical_parse_duration("P1M", &sec));
	assert(!ical_parse_duration("P1Y", &sec));
	/*
	 * Parser is too lax.
	//assert(!ical_parse_duration("P", &sec));
	 * Durations ought to be strictly ordered
	//assert(!ical_parse_duration("PT1S1H", &sec));
	 * RFC 5545 §3.3.6 does not allow combining weeks and days
	//assert(!ical_parse_duration("PT1W2D", &sec));
	 */

	assert(ical_parse_datetime("20231229T090000", &it));
	time_t uxtime = 0;
	assert(ical_itime_to_utc(&tzsel.lineisl, it, &uxtime));
	assert(uxtime == 1703790000U);
	assert(rop_util_unix_to_nttime(uxtime) == 0x1da39c00e767800ULL);
	assert(ical_datetime_to_utc(&tzsel.lineisl, "20231229T090000", &uxtime));
	assert(uxtime == 1703790000U);
	assert(rop_util_unix_to_nttime(uxtime) == 0x1da39c00e767800ULL);
	return EXIT_SUCCESS;
}

static void t_ical()
{
	printf("ical:\n");
	ical ic;
	auto &c = ic.append_comp("COMPX");
	auto &l = c.append_line("KEY", "VALUE1");
	auto &v = l.append_value();
	v.append_subval("SUBVAL");
	v.append_subval("SUBVAL");

	std::string buf;
	auto err = ic.serialize(buf);
	printf("%s\n", buf.c_str());
	if (err != ecSuccess)
		fprintf(stderr, "%s\n", mapi_strerror(err));
}

static int t_ical_dt()
{
	unsigned int count = 0;
	for (const auto s : dt_values) {
		std::string input = dt_head;
		input += "DTSTART"s + s + "\n";
		std::string dtend = s;
		auto pos = dtend.find("20240101");
		if (pos != dtend.npos)
			memcpy(&dtend[pos], "20240102", 8);
		input += "DTEND"s + std::move(dtend) + "\n";
		char buf[64];
		snprintf(buf, std::size(buf), "DTSTAMP:20231205T%06uZ\n", ++count);
		input += buf;
		snprintf(buf, std::size(buf), "UID:%026u@googlemail.com\n", count);
		input += buf;
		snprintf(buf, std::size(buf), "SUMMARY:event%u\n", count);
		input += dt_foot;

		ical ical;
		printf("\n\n<input>:: \e[32m%s\e[0m\n", s);
		if (!ical.load_from_str_move(input.data())) {
			fprintf(stderr, "ical_parse unsuccessful\n");
			return EXIT_FAILURE;
		}
		auto mc = oxcical_import_single("UTC", ical, zalloc,
		          ee_get_propids, oxcmail_username_to_entryid);
		if (mc == nullptr) {
			fprintf(stderr, "oxcical_import unsuccessful\n");
			return EXIT_FAILURE;
		}
		ical = {};
		auto id2user = [](unsigned int, std::string &) -> ec_error_t { return ecNotFound; };
		if (!oxcical_export(mc.get(), "-", ical, "x500", zalloc, ee_get_propids, id2user)) {
			fprintf(stderr, "oxcical_export unsuccessful\n");
			return EXIT_FAILURE;
		}
		std::string outbuf;
		auto err = ical.serialize(outbuf);
		if (err != ecSuccess) {
			fprintf(stderr, "ical::serialize: %s\n", mapi_strerror(err));
			return EXIT_FAILURE;
		}
		printf("<output>:\n\e[31m");
		for (auto &line : gx_split(outbuf, '\n'))
			if (strncmp(line.c_str(), "DTSTART", 7) == 0 ||
			    strncmp(line.c_str(), "X-MICROSOFT-CDO-ALLDAYEVENT:", 28) == 0)
				printf("%s\n", line.c_str());
		printf("\e[0m\n");
	}
	return EXIT_SUCCESS;
}

static int t_rrule()
{
	std::string head =
		"BEGIN:VCALENDAR\n"
		"VERSION:2.0\n"
		"BEGIN:VEVENT\n"
		"CREATED:20170427T181700Z\n"
		"LAST-MODIFIED:20250609T051307Z\n"
		"DTSTAMP:20250609T051307Z\n"
		"UID:74d6b21d-d73c-4cac-af61-6925d1882b30\n"
		"SUMMARY:x\n";
	static constexpr char foot[] =
		"DTSTART;TZID=Europe/Berlin:20150830T110000\n"
		"DTEND;TZID=Europe/Berlin:20150830T180000\n"
		"CLASS:PUBLIC\n"
		"TRANSP:OPAQUE\n"
		"X-MICROSOFT-CDO-INTENDEDSTATUS:BUSY\n"
		"LOCATION:Irgendwo\n"
		"SEQUENCE:0\n"
		"X-MICROSOFT-CDO-OWNER-CRITICAL-CHANGE:20160104T085628Z\n"
		"X-MICROSOFT-CDO-ATTENDEE-CRITICAL-CHANGE:20160104T085628Z\n"
		"X-MICROSOFT-CDO-APPT-SEQUENCE:0\n"
		"X-MICROSOFT-CDO-OWNERAPPTID:-1\n"
		"X-MICROSOFT-CDO-ALLDAYEVENT:FALSE\n"
		"END:VEVENT\n"
		"END:VCALENDAR\n";

	ical icalin;
	auto input = head + "RRULE:FREQ=MONTHLY;BYDAY=2MO\n" + foot;
	bool succ = icalin.load_from_str_move(input.data());
	if (!succ)
		return EXIT_FAILURE;
	auto msg = oxcical_import_single("UTC", icalin, zalloc, ee_get_propids,
	           oxcmail_username_to_entryid);
	assert(msg != nullptr);

	input = head + "RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=8\n" + foot;
	succ = icalin.load_from_str_move(input.data());
	if (!succ)
		return EXIT_FAILURE;
	msg = oxcical_import_single("UTC", icalin, zalloc, ee_get_propids,
	      oxcmail_username_to_entryid);
	assert(msg != nullptr);
	return EXIT_SUCCESS;
}

int main()
{
	auto ret = t_ical_api();
	if (ret != EXIT_SUCCESS)
		return ret;

	t_mime();
	t_card();
	t_ical();
	ret = t_ical_dt();
	if (ret != EXIT_SUCCESS)
		return ret;
	ret = t_rrule();
	if (ret != EXIT_SUCCESS)
		return ret;
	return EXIT_SUCCESS;
}
