// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 grommunio GmbH
// This file is part of Gromox.
/* Example program for incremental change synchronization */
#include <cstdio>
#include <unistd.h>
#include <libHX/scope.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapi_types.hpp>
#include <gromox/paths.h>
#include <gromox/rop_util.hpp>

using namespace gromox;
using LLU = unsigned long long;

static char *g_storedir;

static int do_mbox()
{
	/*
	 * This does not return the root entry itself, just its subordinates.
	 * Might want to refine later.
	 */
	auto root_fid = rop_util_make_eid_ex(1, PRIVATE_FID_ROOT);

	/* local state */
	auto given   = idset::create(idset::type::id_loose);
	auto seen    = idset::create(idset::type::id_loose);
	uint64_t last_cn = 0;


	while (1) {
		EID_ARRAY new_given{}, deleted_fids{};
		FOLDER_CHANGES changes{};
		uint64_t new_cn = 0;

		printf("HSYNC(given=[%zu folders], seen=[%zu folders]):\n",
			given->nelem(), seen->nelem());
		if (!exmdb_client->get_hierarchy_sync(g_storedir, root_fid, nullptr,
		    given.get(), seen.get(), &changes, &new_cn, &new_given,
		    &deleted_fids)) {
			printf("get_hierarchy_sync RPC failed\n");
			return -1;
		}
		printf("\tchangenumber=%llu [%s]\n",
			LLU{rop_util_get_gc_value(new_cn)},
			last_cn == new_cn ?
				"Hierarchy unchanged" :
				"Hierarchy was changed");
		if (last_cn == new_cn && isatty(STDOUT_FILENO))
			printf("\e[1;30m");
		printf("\tgiven_fids=[%zu folders] {", new_given.size());
		for (const auto i : new_given) {
			printf("%llu,", LLU{rop_util_get_gc_value(i)});
			given->append(i);
			seen->append(i);
		}
		printf("}\n");
		printf("\tdeleted_fids=[%zu folders] {", deleted_fids.size());
		for (const auto i : deleted_fids) {
			printf("%llu,", LLU{rop_util_get_gc_value(i)});
			given->remove(i);
			seen->remove(i);
		}
		printf("}\n\n");
		if (last_cn == new_cn && isatty(STDOUT_FILENO))
			printf("\e[0m");

		last_cn = new_cn;
		sleep(3);
	}

	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s MBOXDIR\n", argv[0]);
		return EXIT_FAILURE;
	}

	exmdb_client.emplace(1, 0);
	auto cleanup_0 = HX::make_scope_exit([]() { exmdb_client.reset(); });
	if (exmdb_client_run(PKGSYSCONFDIR) != 0)
		return EXIT_FAILURE;

	g_storedir = argv[1];
	return do_mbox() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
