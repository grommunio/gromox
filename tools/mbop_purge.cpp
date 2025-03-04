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
		fprintf(stderr, "mbop/purge: No folders specified, no action taken.\n");
	auto age = rop_util_unix_to_nttime(time(nullptr) - HX_strtoull_sec(znul(g_age_str), nullptr));
	while (*++argv != nullptr) {
		uint64_t id = strtoull(*argv, nullptr, 0);
		eid_t eid = id == 0 ? gi_lookup_eid_by_name(g_storedir, *argv) :
		            rop_util_make_eid_ex(1, id);
		if (eid == 0) {
			fprintf(stderr, "Not recognized/found: \"%s\"\n", *argv);
			return EXIT_FAILURE;
		}
		unsigned int flags = g_recursive ? DEL_FOLDERS : 0;
		auto ok = exmdb_client->purge_softdelete(g_storedir, nullptr,
		          eid, flags, age);
		if (!ok) {
			fprintf(stderr, "purge_softdel %s failed\n", *argv);
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

}
