// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <libHX/option.h>
#include <gromox/exmdb_rpc.hpp>
#include "genimport.hpp"

static uint64_t g_folderid;
static char *g_username;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'f', HXTYPE_UINT64, &g_folderid, nullptr, nullptr, 0, "Folder ID"},
	{nullptr, 'u', HXTYPE_STRING, &g_username, nullptr, nullptr, 0, "Username of store to import to", "EMAILADDR"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static void terse_help()
{
	fprintf(stderr, "Usage: gromox-delmsg -u a@b.de -f folder_id message_id[,...]\n");
}

int main(int argc, const char **argv)
{
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (g_username == nullptr || g_folderid == 0) {
		terse_help();
		return EXIT_FAILURE;
	}
	gi_setup_early(g_username);
	if (gi_setup() != EXIT_SUCCESS)
		return EXIT_FAILURE;
	std::vector<uint64_t> eids;
	while (*++argv != nullptr)
		eids.push_back(rop_util_make_eid_ex(1, strtoull(*argv, nullptr, 0)));
	EID_ARRAY ea;
	ea.count = eids.size();
	ea.pids = eids.data();
	BOOL partial = false;
	/*
	 * Always do hard deletion, because the message really needs to go away.
	 * Other tools/programs might pick it up otherwise.
	 */
	if (!exmdb_client_remote::delete_messages(g_storedir, g_user_id, 65001,
	    nullptr, rop_util_make_eid_ex(1, g_folderid), &ea, true, &partial)) {
		printf("RPC was rejected.\n");
		return EXIT_FAILURE;
	}
	if (partial) {
		printf("Partial completion\n");
		return EXIT_SUCCESS;
	}
	printf("%zu messages deleted\n", eids.size());
	return EXIT_SUCCESS;
}
