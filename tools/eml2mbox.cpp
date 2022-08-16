// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <libHX/io.h>
#include <libHX/string.h>
#include <gromox/fileio.h>
#include <gromox/scope.hpp>

using namespace gromox;

static int do_file(const char *filename)
{
	std::unique_ptr<FILE, file_deleter> fp(fopen(filename, "r"));
	if (fp == nullptr) {
		fprintf(stderr, "Could not open %s: %s\n",
		        filename, strerror(errno));
		return EXIT_FAILURE;
	}
	auto now = time(nullptr);
	auto now_s = ctime(&now);
	if (now_s != nullptr)
		HX_chomp(now_s);
	printf("From MAILER-DAEMON %s\n", now_s != nullptr ? now_s : "Sat Jan  1 00:00:00 2022");
	hxmc_t *ln = nullptr;
	auto cl_0 = make_scope_exit([&]() { HXmc_free(ln); });
	while (HX_getl(&ln, fp.get()) != nullptr) {
		HX_chomp(ln);
		printf("%s\n", ln);
		if (*ln == '\0')
			break;
	}
	while (HX_getl(&ln, fp.get()) != nullptr) {
		HX_chomp(ln);
		if (strncmp(ln, "From ", 5) == 0)
			printf(">");
		printf("%s\n", ln);
	}
	printf("\n");
	return EXIT_SUCCESS;
}

static int do_stdin()
{
	hxmc_t *ln = nullptr;
	auto cl_0 = make_scope_exit([&]() { HXmc_free(ln); });
	while (HX_getl(&ln, stdin) != nullptr){
		auto ret = do_file(HX_chomp(ln));
		if (ret != EXIT_SUCCESS)
			return ret;
	}
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	while (--argc > 0) {
		++argv;
		auto ret = strcmp(*argv, "-") == 0 ? do_stdin() : do_file(*argv);
		if (ret != EXIT_SUCCESS)
			return ret;
	}
	return EXIT_SUCCESS;
}
