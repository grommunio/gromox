// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gromox/mapidefs.h>
#include <gromox/fileio.h>
#include <gromox/util.hpp>

using namespace gromox;

[[noreturn]] static void usage()
{
	fprintf(stderr, "Usage: test -d x.zst\n");
	exit(EXIT_FAILURE);
}

static int decomp(int argc, char **argv)
{
	if (argc < 2)
		usage();
	BINARY bin{};
	auto ret = gx_decompress_file(argv[1], bin, malloc, realloc);
	if (ret != 0) {
		fprintf(stderr, "gx_decompress %s: %s\n", argv[1], strerror(ret));
		return EXIT_FAILURE;
	}
	fprintf(stderr, "Uncompressed size: %zu\n",
		static_cast<size_t>(bin.cb));
	if (bin.pb[bin.cb] != '\0') {
		fprintf(stderr, "NUL check failed\n");
		return EXIT_FAILURE;
	}
	free(bin.pv);
	return EXIT_SUCCESS;
}

static int comp(int argc, char **argv)
{
	if (argc < 3)
		usage();
	auto bufsize = strtoul(argv[1], nullptr, 0);
	auto buf = std::make_unique<char[]>(bufsize + 1);
	randstring(buf.get(), bufsize);
	auto ret = gx_compress_tofile(std::string(buf.get(), bufsize), argv[2]);
	if (ret != 0)
		mlog(LV_ERR, "gx_compress_tofile %s: %s", argv[2], strerror(ret));
	return EXIT_SUCCESS;
}

static int detsize(int argc, char **argv)
{
	while (*++argv != nullptr)
		printf("%s: %zu bytes\n", *argv, gx_decompressed_size(*argv));
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	if (argc < 2)
		usage();
	if (strcmp(argv[1], "-d") == 0)
		return decomp(argc - 1, argv + 1);
	if (strcmp(argv[1], "-s") == 0)
		return detsize(argc - 1, argv + 1);
	if (strcmp(argv[1], "-z") == 0)
		return comp(argc - 1, argv + 1);
	usage();
}
