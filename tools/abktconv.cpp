// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>
#include <libHX/io.h>
#include <libHX/option.h>
#include <gromox/oxoabkt.hpp>
#include <gromox/paths.h>
#include <gromox/textmaps.hpp>

using namespace gromox;

static unsigned int g_tobin, g_tojson, g_dogap;
static cpid_t g_cpid = CP_ACP;

static constexpr struct HXoption g_options_table[] = {
	{nullptr, 'b', HXTYPE_NONE, &g_tobin, nullptr, nullptr, 0, "Select (from-json-)to-binary mode"},
	{nullptr, 'c', HXTYPE_UINT, &g_cpid, nullptr, nullptr, 0, "Read/write using code page", "ID"},
	{nullptr, 'g', HXTYPE_NONE, &g_dogap, nullptr, nullptr, 0, "Emit Exchange string table gap"},
	{nullptr, 'j', HXTYPE_NONE, &g_tojson, nullptr, nullptr, 0, "Select (from-binary-)to-json mode"},
	{nullptr, 'w', HXTYPE_VAL, &g_cpid, nullptr, nullptr, 0, "Read/write using Unicode"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

int main(int argc, const char **argv)
{
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	textmaps_init(PKGDATADIR);
	if (g_cpid != CP_ACP && cpid_to_cset(g_cpid) == nullptr) {
		printf("Unknown codepage %u\n", g_cpid);
		return EXIT_FAILURE;
	} else if (g_tobin && g_tojson) {
		printf("Cannot use both -b and -j\n");
		return EXIT_FAILURE;
	}

	size_t slurp_len = 0;
	std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_fd(STDIN_FILENO, &slurp_len));
	if (slurp_data == nullptr) {
		fprintf(stderr, "HX_slurp_fd stdin: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	std::string_view all(slurp_data.get(), slurp_len);
	if (g_tojson) {
		try {
			auto out = abkt_tojson(std::move(all), g_cpid);
			puts(out.c_str());
		} catch (const std::runtime_error &e) {
			printf("abkt_read: %s\n", e.what());
		}
	} else if (g_tobin) {
		try {
			auto out = abkt_tobinary(std::move(all), g_cpid, g_dogap);
			write(STDOUT_FILENO, out.data(), out.size());
		} catch (const std::runtime_error &e) {
			printf("abkt_write: %s\n", e.what());
		}
	}
	return EXIT_SUCCESS;
}
