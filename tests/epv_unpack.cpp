// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <unistd.h>
#include <libHX/io.h>
#include <libHX/option.h>
#ifdef HAVE_ESEDB
#	include <libesedb.h>
#endif
#include "../tools/edb_pack.hpp"

using namespace gromox;

#ifdef HAVE_ESEDB
#define TOU8(s) reinterpret_cast<uint8_t *>(s)
#define TOCU8(s) reinterpret_cast<const uint8_t *>(s)
extern "C" {
/* exported but not in header */
int libesedb_compression_decompress_get_size(const uint8_t *zd, size_t zdsize, size_t *udsize, void *);
int libesedb_compression_decompress(const uint8_t *zd, size_t zdsize, uint8_t *udata, size_t udsize, void *);
}
#endif

static unsigned int g_decompress;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_VAL, &g_decompress, nullptr, nullptr, 1, "Decompress SeparatedProps"},
	{nullptr, 'C', HXTYPE_VAL, &g_decompress, nullptr, nullptr, 2, "Decompress SeparatedProps and decode"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static int do_mem(const void *data, size_t len)
{
	edb_pull ep;
	ep.init(data, len, malloc, EXT_FLAG_UTF16 | EXT_FLAG_WCOUNT);
	TPROPVAL_ARRAY props{};
	auto ret = ep.g_edb_propval_a(&props);
	if (ret != pack_result::ok) {
		fprintf(stderr, "Unpack failed with status %d\n", static_cast<int>(ret));
		return EXIT_FAILURE;
	}
	if (props.ppropval == nullptr)
		return EXIT_SUCCESS;
	for (unsigned int i = 0; i < props.count; ++i)
		printf("%08xh:%s\n", props.ppropval[i].proptag,
		       props.ppropval[i].value_repr().c_str());
	return EXIT_SUCCESS;
}

static int do_decompress(std::unique_ptr<char[], stdlib_delete> &&zdata, size_t zdsize)
{
#ifdef HAVE_ESEDB
	size_t udsize = 0;
	if (libesedb_compression_decompress_get_size(TOCU8(zdata.get()),
	    zdsize, &udsize, nullptr) < 1) {
		fprintf(stderr, "error\n");
		return EXIT_FAILURE;
	}
	std::string udata;
	udata.resize(udsize);
	if (libesedb_compression_decompress(TOCU8(zdata.get()), zdsize,
	    TOU8(udata.data()), udsize, nullptr) < 1) {
		fprintf(stderr, "error\n");
		return EXIT_FAILURE;
	}
	zdata.reset();
	if (g_decompress == 1) {
		write(STDOUT_FILENO, udata.data(), udata.size());
		return EXIT_SUCCESS;
	}
	edb_pull ep;
	ep.init(udata.data(), udata.size(), malloc, EXT_FLAG_UTF16 | EXT_FLAG_WCOUNT);
	edb_postproc proc;
	TAGGED_PROPVAL tp{};
	auto ret = ep.g_edb_propval(&tp.pvalue, proc);
	if (ret != pack_result::ok) {
		fprintf(stderr, "decode failed\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
#else
	fprintf(stderr, "Uncompress function not built\n");
	return EXIT_FAILURE;
#endif
}

static int do_file(const char *file)
{
	size_t slurp_len = 0;
	std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_file(file, &slurp_len));
	if (slurp_data == nullptr) {
		fprintf(stderr, "%s: %s\n", file, strerror(errno));
		return EXIT_FAILURE;
	}
	if (g_decompress > 0)
		return do_decompress(std::move(slurp_data), slurp_len);
	return do_mem(slurp_data.get(), slurp_len);
}

static void terse_help()
{
	fprintf(stderr, "Usage: epv_unpack [-c|-C|-?] [files...]\n");
}

int main(int argc, const char **argv)
{
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (argc < 2) {
		terse_help();
		return EXIT_FAILURE;
	}
	while (*++argv != nullptr) {
		fprintf(stderr, ">> %s\n", *argv);
		auto ret = do_file(*argv);
		if (ret != EXIT_SUCCESS)
			return ret;
	}
	return EXIT_SUCCESS;
}
