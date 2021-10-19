// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <new>
#include <libHX/option.h>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/tpropval_array.hpp>
#include "genimport.hpp"

namespace exmdb_client = exmdb_client_remote;
static constexpr unsigned int codepage = 65001;
static char *g_primail;

static const struct HXoption g_options_table[] = {
	{nullptr, 'e', HXTYPE_STRING, &g_primail, nullptr, nullptr, 0, "Primary e-mail address of store", "ADDR"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static inline bool change_key_ok(const BINARY &b)
{
	/* Not much else to do. OXCFXICS §2.2.2.2 */
	return b.cb >= 16 && b.cb <= 24;
}

static inline bool pcl_ok(const BINARY &b)
{
	std::unique_ptr<PCL, gi_delete> pcl(pcl_init());
	if (pcl == nullptr)
		throw std::bad_alloc();
	return pcl_deserialize(pcl.get(), &b);
}

static inline bool needs_repair(const TPROPVAL_ARRAY *tp)
{
	auto ckey = static_cast<const BINARY *>(tpropval_array_get_propval(tp, PR_CHANGE_KEY));
	auto pcl  = static_cast<const BINARY *>(tpropval_array_get_propval(tp, PR_PREDECESSOR_CHANGE_LIST));
	return !change_key_ok(*ckey) || !pcl_ok(*pcl);
}


static int repair_folder(uint64_t fid)
{
	printf("%llxh assign ", static_cast<unsigned long long>(rop_util_get_gc_value(fid)));
	fflush(stdout);

	tpropval_array_ptr props(tpropval_array_init());
	if (props == nullptr)
		return -ENOMEM;
	uint64_t change_num = 0;
	if (!exmdb_client::allocate_cn(g_storedir, &change_num)) {
		fprintf(stderr, "exm: allocate_cn(fld) RPC failed\n");
		return -EIO;
	}
	printf("cn %llxh ", static_cast<unsigned long long>(change_num));
	auto ret = exm_set_change_keys(props.get(), change_num);
	if (ret < 0)
		return ret;
	PROBLEM_ARRAY problems;
	if (!exmdb_client::set_folder_properties(g_storedir,
	    codepage, fid, props.get(), &problems)) {
		fprintf(stderr, "exm: set_folder_properties RPC failed\n");
		return -EIO;
	}
	printf("done\n");
	return 0;
}

static int repair_mbox()
{
	static constexpr uint32_t tags[] =
		{PROP_TAG_FOLDERID, PR_CHANGE_KEY, PR_PREDECESSOR_CHANGE_LIST};
	static constexpr PROPTAG_ARRAY ptags[] = {3, deconst(tags)};
	uint32_t table_id = 0, row_num = 0;
	uint64_t root_fld = g_public_folder ? rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) :
	                    rop_util_make_eid_ex(1, PUBLIC_FID_ROOT);
	/*
	 * This does not return the root entry itself, just its subordinates.
	 * Might want to refine later.
	 */
	if (!exmdb_client::load_hierarchy_table(g_storedir, root_fld,
	    nullptr, TABLE_FLAG_DEPTH, nullptr, &table_id, &row_num)) {
		fprintf(stderr, "exm: load_hierarchy_table RPC failed\n");
		return -EIO;
	}
	TARRAY_SET tset{};
	if (!exmdb_client::query_table(g_storedir, nullptr, codepage, table_id,
	    ptags, 0, row_num, &tset)) {
		fprintf(stderr, "exm: query_table RPC failed\n");
		return -EIO;
	}
	exmdb_client::unload_table(g_storedir, table_id);
	printf("Hierarchy discovery: %u folders\n", tset.count);
	for (size_t i = 0; i < tset.count; ++i) {
		auto fid = static_cast<const uint64_t *>(tpropval_array_get_propval(tset.pparray[i], PROP_TAG_FOLDERID));
		if (fid == nullptr)
			continue;
		try {
			if (!needs_repair(tset.pparray[i])) {
				printf("%llxh unchanged\n", static_cast<unsigned long long>(rop_util_get_gc_value(*fid)));
				continue;
			}
		} catch (const std::bad_alloc &) {
			return -ENOMEM;
		}
		auto ret = repair_folder(*fid);
		if (ret != 0)
			return ret;
	}
	return 0;
}

int main(int argc, const char **argv)
{
	if (HX_getopt(g_options_table, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (g_primail == nullptr) {
		fprintf(stderr, "Usage: cgkrepair -e primary_mailaddr\n");
		return EXIT_FAILURE;
	}
	gi_setup_early(g_primail);
	if (gi_setup() != EXIT_SUCCESS)
		return EXIT_FAILURE;
	auto ret = repair_mbox();
	if (ret == -ENOMEM)
		fprintf(stderr, "Insufficient system memory.\n");
	if (ret != 0) {
		fprintf(stderr, "The operation did not complete.\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
