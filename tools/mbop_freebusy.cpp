// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <vector>
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

static int xmktime(const char *str, time_t *out)
{
	char *end = nullptr;
	*out = strtol(str, &end, 0);
	if (end == nullptr || *end == '\0')
		/* looks like we've got outselves a unixts */
		return 0;
	struct tm tm{};
	end = strptime(str, "%FT%T", &tm);
	if (end != nullptr && *end != '\0') {
		fprintf(stderr, "\"%s\" not understood, error at \"%s\". Required format is \"2024-01-01T00:00:00\" [always local system time] or unixtime.\n", g_start_txt, end);
		return -1;
	}
	tm.tm_wday = -1;
	*out = mktime(&tm);
	if (*out == -1 && tm.tm_wday == -1) {
		fprintf(stderr, "\"%s\" not understood by mktime\n", g_start_txt);
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
		fprintf(stderr, "get_freebusy call not successful\n");
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
