// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <libHX/ctype_helper.h>
#include <libHX/option.h>
#include <gromox/freebusy.hpp>
#include <gromox/mapidefs.h>
#include "genimport.hpp"
#include "mbop.hpp"

using namespace gromox;

namespace getfreebusy {

static constexpr struct HXoption g_options_table[] = {
	{{}, 'a', HXTYPE_STRING, {}, {}, {}, 0, "Start time (localtime; respects $TZ)"},
	{{}, 'b', HXTYPE_STRING, {}, {}, {}, 0, "End time (localtime; respects $TZ)"},
	{{}, 'x', HXTYPE_STRING, {}, {}, {}, 0, "Requestor account name (not the same as -d/-u)"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

static bool zone_extract(const char *s, int *west, char **end)
{
	if (s[0] == 'Z' && s[1] == '\0') {
		*end = deconst(s + 1);
		*west = 0;
		return true;
	} else if (s[0] != '+' && s[0] != '-') {
		*end = deconst(s);
		return false;
	} else if (!HX_isdigit(s[1]) || !HX_isdigit(s[2]) || !HX_isdigit(s[3]) || !HX_isdigit(s[4])) {
		*end = deconst(s);
		return false;
	}
	int min = (s[4] - '0') + (s[3] - '0') * 10 +
		  (s[2] - '0') * 60 + (s[1] - '0') * 600;
	*west = s[0] == '-' ? min : -min;
	*end = deconst(s + 5);
	return true;
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
		mbop_fprintf(stderr, "\"%s\" not understood. Required format is \"2024-01-01T00:00:00\" (withour or with zone offset), or unixtime.\n", str);
		return -1;
	}
	int min_west = 0;
	bool has_zone = false;
	if (end != nullptr)
		has_zone = zone_extract(end, &min_west, &end);
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
	const char *g_start_txt = nullptr, *g_end_txt = nullptr, *g_requestor = nullptr;
	HXopt6_auto_result result;
	if (HX_getopt6(g_options_table, argc, argv, &result, HXOPT_USAGEONERR |
	    HXOPT_ITER_OPTS) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;
	for (int i = 0; i < result.nopts; ++i) {
		switch (result.desc[i]->sh) {
		case 'a': g_start_txt = result.oarg[i]; break;
		case 'b': g_end_txt   = result.oarg[i]; break;
		case 'x': g_requestor = result.oarg[i]; break;
		}
	}

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
	printf("Results (%zu row(s)):\n", fbout.size());
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
