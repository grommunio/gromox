// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <libHX/ctype_helper.h>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <gromox/freebusy.hpp>
#include <gromox/mapidefs.h>
#include "genimport.hpp"
#include "mbop.hpp"

using namespace gromox;

namespace getfreebusy {

static char *g_start_txt, *g_end_txt, *g_requestor;
static constexpr struct HXoption g_options_table[] = {
	{nullptr, 'a', HXTYPE_STRING, &g_start_txt, {}, {}, 0, "Start time (localtime; respects $TZ)"},
	{nullptr, 'b', HXTYPE_STRING, &g_end_txt, {}, {}, 0, "End time (localtime; respects $TZ)"},
	{nullptr, 'x', HXTYPE_STRING, &g_requestor, {}, {}, 0, "Requestor account name (not the same as -d/-u)"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

static bool zone_present(const char *s)
{
	if (s[0] != '+' && s[0] != '-')
		return false;
	return HX_isdigit(s[1]) && HX_isdigit(s[2]) && HX_isdigit(s[3]) && HX_isdigit(s[4]);
}

static int minutes_west(const char *s)
{
	int min = (s[4] - '0') + (s[3] - '0') * 10 +
	          (s[2] - '0') * 60 + (s[1] - '0') * 600;
	return s[0] == '-' ? min : -min;
}

static int xmktime(const char *str, time_t *out)
{
	char *end = nullptr;
	*out = strtol(str, &end, 0);
	if (end == nullptr || *end == '\0')
		/* looks like we've got ourselves a unixts */
		return 0;
	struct tm tm{};
	end = strptime(str, "%FT%T", &tm);
	if (end == nullptr) {
		mbop_fprintf(stderr, "\"%s\" not understood. Required format is \"2024-01-01T00:00:00\" [always local system time] or unixtime.\n", str);
		return -1;
	}
	auto has_zone = end != nullptr && zone_present(end);
	unsigned int min_west = 0;
	if (has_zone) {
		min_west = minutes_west(end);
		end += 5;
	}
	if (end != nullptr && *end != '\0') {
		mbop_fprintf(stderr, "Don't know what to do with: \"%s\". Remove it.\n", end);
		return -1;
	}
	tm.tm_wday = -1;
	tm.tm_isdst = -1;
	*out = has_zone ? timegm(&tm) + 60 * min_west : mktime(&tm);
	if (*out == -1 && tm.tm_wday == -1) {
		mbop_fprintf(stderr, "\"%s\" not understood by mktime\n", str);
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (HX_getopt5(g_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;
	auto cl_0 = HX::make_scope_exit([=]() { HX_zvecfree(argv); });
	time_t start_time = -1, end_time = -1;
	if (g_start_txt != nullptr && xmktime(g_start_txt, &start_time) < 0)
		return EXIT_PARAM;
	if (g_end_txt != nullptr && xmktime(g_end_txt, &end_time) < 0)
		return EXIT_PARAM;
	std::vector<freebusy_event> fbout;
	if (!get_freebusy(g_requestor, g_storedir, start_time, end_time, fbout)) {
		mbop_fprintf(stderr, "get_freebusy call not successful\n");
		return EXIT_FAILURE;
	}
	printf("Results (%zu rows):\n", fbout.size());
	for (const auto &e : fbout) {
		char start_tx[64], end_tx[64];
		struct tm tm{};
		localtime_r(&e.start_time, &tm);
		strftime(start_tx, std::size(start_tx), "%FT%T", &tm);
		localtime_r(&e.end_time, &tm);
		strftime(end_tx, std::size(end_tx), "%FT%T", &tm);
		printf("{start=%s, end=%s, busy=%u, details?=%u, meeting?=%u, "
		       "recurring?=%u, exception?=%u, reminder?=%u, private?=%u, "
		       "id=%s, subject=\"%s\", location=\"%s\"}}\n",
		       start_tx, end_tx, e.busy_status, e.has_details,
		       e.is_meeting, e.is_recurring, e.is_exception,
		       e.is_reminderset, e.is_private, e.m_id.c_str(),
		       e.m_subject.c_str(), e.m_location.c_str());
	}
	return EXIT_SUCCESS;
}

}
