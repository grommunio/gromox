// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <gromox/mail_func.hpp>
#undef assert
#define assert(x) do { if (!(x)) { printf("%s failed\n", #x); return EXIT_FAILURE; } } while (false)
using namespace gromox;

static int run(const char *in, std::vector<std::string> &argv)
{
	char buf[256];
	auto len = strlen(in);
	memcpy(buf, in, len + 1);
	return parse_imap_args(buf, len, argv);
}

int main()
{
	std::vector<std::string> argv;
	/* plain command */
	assert(run("A1 LOGIN user pass", argv) == 4);
	/* well-formed inline literal is accepted */
	assert(run("A1 LOGIN user {4}pass", argv) > 0);
	/* length larger than the bytes present must be rejected, not read OOB */
	assert(run("A1 LOGIN user {999999}x", argv) == -1);
	/* a value that overflows strtoul must not wrap ptr before the buffer */
	assert(run("A1 LOGIN user {99999999999999999999}x", argv) == -1);
	printf("OK\n");
	return EXIT_SUCCESS;
}
