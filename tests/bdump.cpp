// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <memory>
#include <unistd.h>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/util.hpp>

using namespace gromox;

enum { D_NONE, D_RESTRICT, D_ACTIONS, };
static unsigned int g_decode, g_hex2bin;
static constexpr struct HXoption g_options_table[] = {
	{"act", 'A', HXTYPE_VAL, &g_decode, nullptr, nullptr, D_ACTIONS, "Decode rule actions"},
	{"pack", 'p', HXTYPE_NONE, &g_hex2bin, nullptr, nullptr, 0, "Use hex2bin"},
	{"res", 'r', HXTYPE_VAL, &g_decode, nullptr, nullptr, D_RESTRICT, "Decode restriction"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

int main(int argc, char **argv)
{
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt6(g_options_table, argc, argv, nullptr,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;

	size_t slurp_len = 0;
	std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_fd(STDIN_FILENO, &slurp_len));
	if (slurp_data == nullptr)
		return EXIT_FAILURE;
	std::string unhexed;
	EXT_PULL ep;
	if (g_hex2bin) {
		unhexed = hex2bin({slurp_data.get(), slurp_len}, HEX2BIN_SKIP);
		ep.init(unhexed.data(), slurp_len / 2, zalloc, 0);
	} else {
		ep.init(slurp_data.get(), slurp_len, zalloc, 0);
	}
	if (g_decode == D_RESTRICT) {
		RESTRICTION rs{};
		if (ep.g_restriction(&rs) != pack_result::ok)
			return EXIT_FAILURE;
		printf("%s\n", rs.repr().c_str());
	} else if (g_decode == D_ACTIONS) {
		RULE_ACTIONS ra{};
		if (ep.g_rule_actions(&ra) != pack_result::ok)
			return EXIT_FAILURE;
		printf("%s\n", ra.repr().c_str());
	}
	return EXIT_SUCCESS;
}
