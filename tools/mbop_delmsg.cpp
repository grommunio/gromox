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
	if (g_folderstr != nullptr)
		g_folderid = gi_lookup_eid_any_way(g_storedir, g_folderstr);
	if (rop_util_get_gc_value(g_folderid) == 0)
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

namespace movemsg {

static constexpr HXoption g_options_table[] = {
	{{}, 'f', HXTYPE_STRING, {}, {}, {}, 0, "Source folder", "NAME/ID"},
	{{}, 't', HXTYPE_STRING, {}, {}, {}, 0, "Destination folder", "NAME/ID"},
	{"copy", 'C', HXTYPE_NONE, {}, {}, {}, 0, "Copy instead of move"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

static int help()
{
	fprintf(stderr, "Usage: gromox-mbop -u a@b.de movemsg -f src_folder_id -t dst_folder_id message_id[...]\n");
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
		if (result.desc[i]->sh == 'f')
			g_srcstr = result.oarg[i];
		else if (result.desc[i]->sh == 't')
			g_dststr = result.oarg[i];
		else if (result.desc[i]->sh == 'c')
			g_copy = true;
	}
	if (g_srcstr != nullptr)
		g_srcfid = gi_lookup_eid_any_way(g_storedir, g_srcstr);
	if (g_dststr != nullptr)
		g_dstfid = gi_lookup_eid_any_way(g_storedir, g_dststr);
	if (g_srcfid.gcv() == 0 || g_dstfid.gcv() == 0)
		return help();
	std::vector<eid_t> eids;
	for (int uidx = 0; uidx < result.nargs; ++uidx)
		eids.emplace_back(eid_t{1, strtoul(result.uarg[uidx], nullptr, 0)});
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
		printf("Partial completion! Some of ");
	printf("%zu message(s) %s\n", eids.size(), g_copy ? "copied" : "moved");
	return EXIT_SUCCESS;
}

}
