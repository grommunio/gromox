// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdlib>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/paths.h>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>

using namespace gromox;
namespace exmdb_client = exmdb_client_remote;

static alloc_context g_alloc_mgr;

int main(int argc, char **argv)
{
	exmdb_rpc_alloc = [](size_t z) { return g_alloc_mgr.alloc(z); };
	exmdb_rpc_free = [](void *) {};
	exmdb_client_init(1, 0);
	auto cl_0 = make_scope_exit(exmdb_client_stop);
	if (exmdb_client_run(PKGSYSCONFDIR) != 0)
		return EXIT_FAILURE;

	static constexpr STORE_ENTRYID other_store = {0, 0, 0, 0, {}, 0, deconst(""), deconst("")};
	const char *g_storedir = argc == 1 ? "" : argv[1];
	char *newdir = nullptr;
	unsigned int user_id = 0, domain_id = 0;

	printf("req 1\n");
	if (!exmdb_client::store_eid_to_user(g_storedir, &other_store, &newdir,
	    &user_id, &domain_id))
		mlog(LV_DEBUG, "store_eid_to_user failed as expected");
	else
		mlog(LV_ERR, "store_eid_to_user unexpectedly succeeded");
	// Connection should have died by now
	printf("req 2\n");

	static constexpr uint32_t tags[] = {PR_STORE_RECORD_KEY};
	static constexpr PROPTAG_ARRAY ptags[] = {std::size(tags), deconst(tags)};
	TPROPVAL_ARRAY props{};
	if (!exmdb_client::get_store_properties(g_storedir, CP_UTF8, ptags, &props))
		mlog(LV_ERR, "get_store_properties failed unexpectedly");
	return 0;
}
