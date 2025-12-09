// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022–2025 grommunio GmbH
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

namespace delmsg {

static constexpr HXoption g_options_table[] = {
	{{}, 'f', HXTYPE_STRING, {}, {}, {}, 'f', "Folder ID"},
	{"soft", 0, HXTYPE_NONE, {}, {}, {}, 's', "Soft-delete"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

static int help()
{
	fprintf(stderr, "Usage: gromox-mbop -u a@b.de delmsg -f folder_id message_id[,...]\n");
	return EXIT_PARAM;
}

int main(int argc, char **argv)
{
	bool g_soft = false;
	const char *g_folderstr = nullptr;
	eid_t g_folderid{};

	HXopt6_auto_result result;
	if (HX_getopt6(g_options_table, argc, argv, &result, HXOPT_USAGEONERR |
	    HXOPT_ITER_OA) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;
	for (int i = 0; i < result.nopts; ++i) {
		if (result.desc[i]->val == 's')
			g_soft = true;
		else if (result.desc[i]->val == 'f')
			g_folderstr = result.oarg[i];
	}
	if (g_folderstr != nullptr) {
		char *end = nullptr;
		uint64_t fid = strtoul(g_folderstr, &end, 0);
		if (end == g_folderstr || *end != '\0')
			g_folderid = gi_lookup_eid_by_name(g_storedir, g_folderstr);
		else
			g_folderid = rop_util_make_eid_ex(1, fid);
	}
	if (rop_util_get_gc_value(g_folderid) == 0)
		return help();
	std::vector<eid_t> eids;
	for (int uidx = 0; uidx < result.nargs; ++uidx) {
		eid_t eid = gi_lookup_eid_by_name(g_storedir, result.uarg[uidx]);
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
	uint32_t prev_delc, prev_fldc, curr_delc, curr_fldc;
	delcount(g_folderid, &prev_delc, &prev_fldc);
	if (!exmdb_client->delete_messages(g_storedir, CP_UTF8, nullptr,
	    g_folderid, &ea, !g_soft, &partial)) {
		printf("RPC was rejected.\n");
		return EXIT_FAILURE;
	}
	delcount(g_folderid, &curr_delc, &curr_fldc);
	if (partial)
		printf("Partial completion\n");
	printf("%d message(s) deleted\n", curr_delc - prev_delc);
	return EXIT_SUCCESS;
}

}
