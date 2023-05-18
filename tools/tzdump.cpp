// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.
/*
 * tzdump -f xyz.tzd
 * 	Dump info from the given timezonedef file.
 * tzdump -z [name...]
 * 	Dump info for the given IANA zone name(s), e.g. "Europe/Berlin".
 * tzdump -Z [name...]
 * 	Dump info for the given Windows zone name(s), e.g. "AUS Central".
 */
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <memory>
#include <gromox/fileio.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/util.hpp>
#include <libHX/io.h>
#include <cstdlib>

using namespace gromox;

static void d_systime(const SYSTEMTIME &t)
{
	printf("{%d-%02d-%02d dow=%d, %02d:%02d:%02d.%03d}",
	       t.year, t.month, t.dayofweek, t.day,
	       t.hour, t.minute, t.second, t.milliseconds);
}

static void d_tzrule(const TZRULE &r)
{
	printf("TZRULE{%u,%u,0x%x,%u,%d,%d,%d,%d,",
	       r.major, r.minor, r.reserved, r.flags,
	       r.year, r.bias, r.standardbias, r.daylightbias);
	d_systime(r.standarddate);
	printf(",");
	d_systime(r.daylightdate);
	printf("}");
}

static void d_tzdef(const TIMEZONEDEFINITION &d)
{
	printf("major = %xh (%u), minor = %xh (%u), reserved = %xh (%u)\n",
	       d.major, d.major, d.minor, d.minor, d.reserved, d.reserved);
	printf("name = %s\n", d.keyname);
	printf("#rules = %xh (%u)\n", d.crules, d.crules);
	for (unsigned int i = 0; i < d.crules; ++i) {
		printf("[%u] ", i);
		d_tzrule(d.prules[i]);
		printf("\n");
	}
}

static int d_raw(const char *name, const void *data, size_t size)
{
	EXT_PULL ep;
	TIMEZONEDEFINITION def;
	ep.init(data, size, zalloc, EXT_FLAG_UTF16);
	if (ep.g_tzdef(&def) != EXT_ERR_SUCCESS) {
		fprintf(stderr, "%s: does not look like a TIMEZONEDEFINITION\n", name);
		return EXIT_FAILURE;
	}
	printf(">>> %s\n", name);
	d_tzdef(def);
	free(def.keyname);
	free(def.prules);
	return EXIT_SUCCESS;
}

static int d_files(int argc, char **argv)
{
	int ret = EXIT_SUCCESS;
	for (; argc-- > 0; ++argv) {
		size_t slurp_len = 0;
		std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_file(*argv, &slurp_len));
		if (slurp_data == nullptr) {
			fprintf(stderr, "Error: Could not read %s: %s\n", *argv, strerror(errno));
			ret = EXIT_FAILURE;
			continue;
		}
		auto r2 = d_raw(*argv, slurp_data.get(), slurp_len);
		if (r2 != EXIT_SUCCESS)
			ret = r2;
	}
	return ret;
}

static int d_zones(int argc, char **argv, bool windows)
{
	int ret = EXIT_SUCCESS;
	for (; argc-- > 0; ++argv) {
		auto zone = *argv;
		if (windows)
			std::replace(&zone[0], &zone[strlen(zone)], ' ', '_');
		auto buf = windows ? wintz_to_tzdef(*argv) : ianatz_to_tzdef(*argv);
		if (buf == nullptr) {
			fprintf(stderr, "%s: zone name not recognized\n", *argv);
			ret = EXIT_FAILURE;
			continue;
		}
		auto r2 = d_raw(*argv, buf->c_str(), buf->size());
		if (r2 != EXIT_SUCCESS)
			ret = r2;
	}
	return ret;
}

int main(int argc, char **argv)
{
	if (argc >= 2 && strcmp(argv[1], "-f") == 0)
		return d_files(argc - 2, &argv[2]);
	else if (argc >= 2 && strcmp(argv[1], "-z") == 0)
		return d_zones(argc - 2, &argv[2], false);
	else if (argc >= 2 && strcmp(argv[1], "-Z") == 0)
		return d_zones(argc - 2, &argv[2], true);
	return EXIT_SUCCESS;
}
