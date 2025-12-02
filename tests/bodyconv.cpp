// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <gromox/element_data.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>

using namespace gromox;

static const std::string lortf_head =
"\x7b\\rtf1\\ansi\\deff0{\\fonttbl{\\f0\\fswiss\\fprq0\\fcharset128 Arial;}}\\plain";
static const std::string lortf_foot = "\x7d";

static int rp_test(const std::string &complete, const char *expout)
{
	std::string outdoc;
	auto at = attachment_list_init();
	auto cl_0 = HX::make_scope_exit([&]() { attachment_list_free(at); });
	if (rtf_to_html(complete, "utf-8", outdoc, at) != ecSuccess) {
		fprintf(stderr, "rtf_to_html failed on:\n%s\n", complete.c_str());
		return -1;
	} else if (html_to_plain(outdoc, CP_UTF8, outdoc) < 0) {
		fprintf(stderr, "rtf+html_to_plain failed on:\n%s\n", complete.c_str());
		return -1;
	}
	HX_chomp(outdoc.data());
	if (strcmp(outdoc.c_str(), expout) != 0) {
		fprintf(stderr, "== Input ==\n%s\n\n== Expected ==\n%s\n\n== Actual output ==\n%s\n",
			complete.c_str(), expout, outdoc.c_str());
		return 1;
	}
	return 0;
}

#define rp_assert(x, y) do { auto kldfgv = rp_test((x), (y)); if (kldfgv != 0) return kldfgv; } while (false)
static int t_rtf_reader()
{
	std::string uncomp;

	rp_assert(lortf_head + "\\dbch\\'89\\'bd" + lortf_foot, "何");
	rp_assert(lortf_head + "\\ansicpg932\\dbch \x89\xbd" + lortf_foot, "何");

	/*
	 * Multi-byte sequences that span an RTF group are handled differently
	 * by various implementations.
	 */
	rp_assert(lortf_head + "\\dbch{\\'89}{\\'bd}" + lortf_foot, "何"); // MSWord
	// rp_assert(lortf_head + "\\dbch{\\'89}{\\'bd}" + lortf_foot, "�ｽ"); // SvxRTF
	return 0;
}

int main()
{
	textmaps_init();
	if (t_rtf_reader() != 0)
		return EXIT_SUCCESS;
	return EXIT_FAILURE;
}
