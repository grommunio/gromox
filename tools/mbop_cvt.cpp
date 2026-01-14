// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025–2026 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <libHX/option.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/mapi_types.hpp>
#include "kdbsub.cpp"
#include "mbop.hpp"

namespace zaddrxlat {

using LLU = unsigned long long;
using namespace gromox;

static unsigned int g_recursive;
static constexpr HXoption g_options_table[] = {
	{{}, 'm', HXTYPE_STRING, {}, {}, {}, 'm', "User map"},
	{{}, 'r', HXTYPE_NONE, &g_recursive, {}, {}, 0, "Operate recursively"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

/**
 * Returns zero on success, or non-zero on error.
 */
static ec_error_t do_message(const kdb_user_map &map, eid_t folder_id, eid_t msg_id)
{
	message_content *ict = nullptr;
	if (!exmdb_client->read_message(g_storedir, nullptr, CP_UTF8, msg_id,
	    &ict) || ict == nullptr) {
		fprintf(stderr, "Unable to read message %llxh\n",
			static_cast<unsigned long long>(msg_id));
		return ecError;
	}

	std::unique_ptr<message_content, mc_delete> ctnt(ict->dup());
	if (subst_addrs_entryids(map, &ctnt->proplist) == 0)
		return ecSuccess; /* nothing to do */

	uint64_t change_num = 0;
	if (!exmdb_client->allocate_cn(g_storedir, &change_num)) {
		fprintf(stderr, "zaxlat: allocate_cn RPC failed\n");
		return ecError;
	}
	auto ret = exm_set_change_keys(&ctnt->proplist, change_num);
	if (ret != 0) {
		fprintf(stderr, "exm: tpropval: %s\n", strerror(-ret));
		return ecError;
	}
	uint64_t outmid{}, outcn{};
	ec_error_t err = ecSuccess;
	if (!exmdb_client->write_message(g_storedir, CP_UTF8, folder_id,
	    ctnt.get(), {}, &outmid, &outcn, &err)) {
		fprintf(stderr, "exm: write_message RPC failed\n");
	} else if (err != ecSuccess) {
		fprintf(stderr, "exm: write_message: %s\n", mapi_strerror(err));
		return err;
	}
	return ecSuccess;
}

static ec_error_t do_folder(const kdb_user_map &umap, eid_t base_folder_id)
{
	std::vector<eid_t> fld_list{base_folder_id};
	if (g_recursive) {
		/* Grab subordinates as well */
		auto err = select_hierarchy(base_folder_id, TABLE_FLAG_DEPTH, fld_list);
		if (err != ecSuccess)
			return err;
	}
	for (auto folder_id : fld_list) {
		fprintf(stderr, "Processing folder %llxh\n", LLU{folder_id});
		std::vector<eid_t> msg_list;
		auto err = select_contents_from_folder(folder_id, 0, nullptr, msg_list);
		if (err != ecSuccess)
			return err;
		for (auto msg_id : msg_list) {
			err = do_message(umap, folder_id, msg_id);
			if (err != ecSuccess)
				return err;
		}
	}
	return ecSuccess;
}

int main(int argc, char **argv)
{
	HXopt6_auto_result result;
	if (HX_getopt6(g_options_table, argc, argv, &result, HXOPT_USAGEONERR |
	    HXOPT_ITER_OA) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;

	const char *umap_file = nullptr;
	for (int i = 0; i < result.nopts; ++i)
		if (result.desc[i]->sh == 'm')
			umap_file = result.oarg[i];
	if (umap_file == nullptr) {
		fprintf(stderr, "zaddrxlat must be used with a user map (-m)\n");
		return EXIT_FAILURE;
	}
	kdb_user_map umap;
	auto err = umap.read(umap_file);
	if (err != 0) {
		fprintf(stderr, "%s: %s\n", umap_file, strerror(err));
		return EXIT_FAILURE;
	}

	for (int i = 0; i < result.nargs; ++i) {
		auto folder_id = gi_lookup_eid_any_way(g_storedir, result.uarg[i]);
		if (folder_id == 0) {
			fprintf(stderr, "Argument not understood: \"%s\"\n", result.uarg[i]);
			return EXIT_FAILURE;
		}
		auto ec_err = do_folder(umap, folder_id);
		if (ec_err != ecSuccess)
			return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

}
