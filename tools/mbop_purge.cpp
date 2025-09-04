// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/rop_util.hpp>
#include "genimport.hpp"
#include "mbop.hpp"

using namespace gromox;

namespace purgesoftdel {

static unsigned int g_recursive;
static const char *g_age_str;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'r', HXTYPE_NONE, &g_recursive, nullptr, nullptr, 0, "Process folders recursively"},
	{nullptr, 't', HXTYPE_STRING, &g_age_str, nullptr, nullptr, 0, "Messages need to be older than...", "TIMESPEC"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

int main(int argc, char **argv)
{
	if (HX_getopt5(g_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;
	auto cl_0 = HX::make_scope_exit([=]() { HX_zvecfree(argv); });
	if (argc < 2)
		mbop_fprintf(stderr, "mbop/purge: No folders specified, no action taken.\n");
	auto age = rop_util_unix_to_nttime(time(nullptr) - HX_strtoull_sec(znul(g_age_str), nullptr));
	for (int uidx = 1; uidx < argc; ++uidx) {
		eid_t eid = gi_lookup_eid_by_name(g_storedir, argv[uidx]);
		if (eid == 0) {
			mbop_fprintf(stderr, "Not recognized/found: \"%s\"\n", argv[uidx]);
			return EXIT_FAILURE;
		}
		unsigned int flags = g_recursive ? DEL_FOLDERS : 0;
		uint32_t st_folders = 0, st_messages = 0;
		uint64_t sz_normal = 0, sz_fai = 0;
		auto ok = exmdb_client->purge_softdelete(g_storedir, nullptr,
		          eid, flags, age, &st_folders, &st_messages,
		          &sz_normal, &sz_fai);
		if (!ok) {
			mbop_fprintf(stderr, "purge_softdel %s failed\n", argv[uidx]);
			return EXIT_FAILURE;
		}
		char nbuf[32], fbuf[32];
		HX_unit_size(nbuf, std::size(nbuf), sz_normal, 0, 0);
		HX_unit_size(fbuf, std::size(fbuf), sz_fai,    0, 0);
		printf("purge_softdelete: deleted %u messages, %u folders, reclaimed %sB (and %sB FAI)\n",
			static_cast<unsigned int>(st_messages),
			static_cast<unsigned int>(st_folders), nbuf, fbuf);
	}
	return EXIT_SUCCESS;
}

}

namespace cgkreset {

static unsigned int g_zero_lastcn, g_purge_pcl;
static constexpr HXoption g_options_table[] = {
	{{}, 'P', HXTYPE_NONE, &g_purge_pcl, {}, {}, 0, "Purge PCL of foreign identifiers"},
	{{}, 'Z', HXTYPE_NONE, &g_zero_lastcn, {}, {}, 0, "Start with CN 0"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

int main(int argc, char **argv)
{
	if (HX_getopt5(g_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;
	auto cl_0 = HX::make_scope_exit([=]() { HX_zvecfree(argv); });
	unsigned int flags = CGKRESET_FOLDERS | CGKRESET_MESSAGES;
	if (g_zero_lastcn)
		flags |= CGKRESET_ZERO_LASTCN;
	if (!exmdb_client->cgkreset(g_storedir, flags)) {
		mbop_fprintf(stderr, "cgkreset %s failed\n", g_storedir);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

}
