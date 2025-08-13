// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/mapidefs.h>
#include <gromox/rop_util.hpp>
#include "genimport.hpp"
#include "mbop.hpp"

using namespace gromox;

namespace delmsg {

static char *g_folderstr;
static eid_t g_folderid;
static unsigned int g_soft;

static constexpr HXoption g_options_table[] = {
	{nullptr, 'f', HXTYPE_STRING, &g_folderstr, nullptr, nullptr, 0, "Folder ID"},
	{"soft", 0, HXTYPE_NONE, &g_soft, nullptr, nullptr, 0, "Soft-delete"},
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
	if (HX_getopt5(g_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;
	auto cl_0 = HX::make_scope_exit([=]() { HX_zvecfree(argv); });
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
	std::vector<uint64_t> eids;
	while (*++argv != nullptr) {
		eid_t eid = gi_lookup_eid_by_name(g_storedir, *argv);
		if (eid == 0) {
			global::mbop_fprintf(stderr, "Not recognized/found: \"%s\"\n", *argv);
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
	printf("%d messages deleted\n", curr_delc - prev_delc);
	return EXIT_SUCCESS;
}

}
