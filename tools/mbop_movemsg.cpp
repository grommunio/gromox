// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <libHX/option.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/mapidefs.h>
#include <gromox/rop_util.hpp>
#include "genimport.hpp"
#include "mbop.hpp"

using namespace gromox;

namespace movemsg {

static constexpr HXoption g_options_table[] = {
	{{}, 'f', HXTYPE_STRING, {}, {}, {}, 'f', "Source folder ID"},
	{{}, 't', HXTYPE_STRING, {}, {}, {}, 't', "Destination folder ID"},
	{"copy", 0, HXTYPE_NONE, {}, {}, {}, 'c', "Copy instead of move"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

static int help()
{
	fprintf(stderr, "Usage: gromox-mbop -u a@b.de movemsg -f src_folder_id -t dst_folder_id message_id...\n");
	return EXIT_PARAM;
}

int main(int argc, char **argv)
{
	bool g_copy = false;
	const char *g_srcstr = nullptr, *g_dststr = nullptr;
	eid_t g_srcfid{}, g_dstfid{};

	HXopt6_auto_result result;
	if (HX_getopt6(g_options_table, argc, argv, &result, HXOPT_USAGEONERR |
	    HXOPT_ITER_OA) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;
	for (int i = 0; i < result.nopts; ++i) {
		if (result.desc[i]->val == 'f')
			g_srcstr = result.oarg[i];
		else if (result.desc[i]->val == 't')
			g_dststr = result.oarg[i];
		else if (result.desc[i]->val == 'c')
			g_copy = true;
	}
	if (g_srcstr != nullptr)
		g_srcfid = gi_lookup_eid_any_way(g_storedir, g_srcstr);
	if (g_dststr != nullptr)
		g_dstfid = gi_lookup_eid_any_way(g_storedir, g_dststr);
	if (rop_util_get_gc_value(g_srcfid) == 0 || rop_util_get_gc_value(g_dstfid) == 0)
		return help();
	std::vector<eid_t> eids;
	for (int uidx = 0; uidx < result.nargs; ++uidx) {
		eid_t eid{1, strtoul(result.uarg[uidx], nullptr, 0)};
		if (eid == 0) {
			mbop_fprintf(stderr, "Not recognized/found: \"%s\"\n", result.uarg[uidx]);
			return EXIT_FAILURE;
		}
		eids.push_back(eid);
	}
	EID_ARRAY ea;
	ea.count = eids.size();
	ea.pids = eids.data();
	BOOL partial = false;
	if (!exmdb_client->movecopy_messages(g_storedir, CP_UTF8, false, nullptr,
	    g_srcfid, g_dstfid, g_copy, &ea, &partial)) {
		printf("RPC was rejected.\n");
		return EXIT_FAILURE;
	}
	if (partial)
		printf("Partial completion\n");
	printf("%zu message(s) %s\n", eids.size(), g_copy ? "copied" : "moved");
	return EXIT_SUCCESS;
}

}
