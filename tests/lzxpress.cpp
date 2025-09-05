// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <unistd.h>
#include <libHX/io.h>
#include <libHX/misc.h>
#ifdef HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif
#include <gromox/defs.h>
#include <gromox/lzxpress.hpp>

using namespace gromox;

int main(int argc, char **argv)
{
	bool decompress = false, randomtest = false;
	int c;
	while ((c = getopt(argc, argv, "Rcd")) >= 0) {
		if (c == 'd')
			decompress = true;
		if (c == 'R')
			randomtest = true;
	}
	if (randomtest) {
		char b1[1], b2[512], outbuf[512];
		size_t z = 0;
		while (1) {
#if defined(__OpenBSD__)
			arc4random_buf(b1, std::size(b1));
#else
			auto ret = getrandom(b1, std::size(b1), 0);
			if (ret < 0 || static_cast<size_t>(ret) != std::size(b1)) {
				perror("getrandom short read");
				return EXIT_FAILURE;
			}
#endif
			auto complen  = lzxpress_compress(b1, std::size(b1), b2, std::size(b2));
			auto ucomplen = lzxpress_decompress(b2, complen, outbuf, std::size(outbuf));
			if (ucomplen != std::size(b1)) {
				fprintf(stderr, "Failed input (%zu):\n", ++z);
				HX_hexdump(stderr, b1, std::size(b1));
				HX_hexdump(stderr, b2, complen);
				HX_hexdump(stderr, outbuf, ucomplen);
				return EXIT_FAILURE;
			}
		}
		return EXIT_SUCCESS;
	}
	size_t slurp_len = 0;
	std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_fd(STDIN_FILENO, &slurp_len));
	if (slurp_data == nullptr) {
		fprintf(stderr, "Unable to read from stdin: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	/*
	 * The API of that lzxpress implementation does not expose streamed
	 * decompression; it's just one-shot. Just allocate a huge chunk and
	 * hope.
	 */
	size_t osize = slurp_len * 10;
	auto outbuf = std::make_unique<char[]>(osize);
	auto ret = decompress ?
	           lzxpress_decompress(slurp_data.get(), slurp_len, outbuf.get(), osize) :
	           lzxpress_compress(slurp_data.get(), slurp_len, outbuf.get(), osize);
	if (ret < 0) {
		fprintf(stderr, "Something went wrong\n");
		return EXIT_FAILURE;
	}
	if (HXio_fullwrite(STDOUT_FILENO, outbuf.get(), ret) < 0)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
