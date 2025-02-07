// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdlib>
#include <vector>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/paths.h>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>

using namespace gromox;
using exmdb_client = exmdb_client_remote;

static alloc_context g_alloc_mgr;

static int t_2209(const char *dir)
{
	static constexpr uint64_t v_zero = 0;
	static constexpr BINARY v_binzero = {0, {.pc = deconst("")}};
	const TAGGED_PROPVAL pvd[] = {
		{PR_COMMENT, deconst("acomment")},
	};
	TAGGED_PROPVAL qvd[std::size(pvd)+4]{};
	const TPROPVAL_ARRAY pvals = {std::size(pvd), deconst(pvd)};
	TPROPVAL_ARRAY qvals = {0, deconst(qvd)};
	std::vector<uint16_t> original_indices;
	PROPERTY_PROBLEM probbuf[std::size(pvd)];
	PROBLEM_ARRAY problems = {0, probbuf};

	for (size_t i = 0; i < pvals.count; ++i) {
		const auto &pv = pvals.ppropval[i];
		if (pv.proptag == PR_ACCESS) {
			problems.emplace_back(i, pv.proptag, ecAccessDenied);
		} else {
			qvals.ppropval[qvals.count++] = pv;
			original_indices.push_back(i);
		}
	}
	qvals.emplace_back(PidTagChangeNumber, &v_zero);
	qvals.emplace_back(PR_CHANGE_KEY, &v_binzero);
	qvals.emplace_back(PR_PREDECESSOR_CHANGE_LIST, &v_binzero);
	qvals.emplace_back(PROP_TAG(PT_I8, 0), &v_zero);

	if (!exmdb_client::set_folder_properties(dir, CP_UTF8,
	    rop_util_make_eid_ex(1, PRIVATE_FID_ROOT), &qvals, &problems)) {
		mlog(LV_ERR, "set_folder_properties failed unexpectedly");
		return EXIT_FAILURE;
	}
	problems.transform(original_indices);
	return EXIT_SUCCESS;
}

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
	static constexpr PROPTAG_ARRAY ptags = {std::size(tags), deconst(tags)};
	TPROPVAL_ARRAY props{};
	if (!exmdb_client::get_store_properties(g_storedir, CP_UTF8, &ptags, &props))
		mlog(LV_ERR, "get_store_properties failed unexpectedly");

	return t_2209(g_storedir);
}
