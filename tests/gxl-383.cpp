// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/paths.h>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>

namespace exmdb_client = exmdb_client_remote;
using namespace gromox;

static uint32_t propid_elist(const char *dir)
{
	const PROPERTY_NAME pn = {MNID_ID, PSETID_ADDRESS, dispidEmailList};
	const PROPNAME_ARRAY pna = {1, deconst(&pn)};
	PROPID_ARRAY pia{};

	if (!exmdb_client::get_named_propids(dir, false, &pna, &pia))
		return 0;
	if (pia.count == 0)
		return 0;
	return PROP_TAG(PT_MV_LONG, pia.ppropid[0]);
}

static int askfor(const char *dir, uint64_t folder_id, uint32_t elist_tag,
    uint16_t sort_count)
{
	const uint32_t letags[] = {PR_NORMALIZED_SUBJECT, elist_tag};
	const PROPTAG_ARRAY tagarr = {std::size(letags), deconst(letags)};
	const SORT_ORDER sort_spec[] = {
		{PROP_TYPE(letags[0]), PROP_ID(letags[0]), 0},
		{PROP_TYPE(letags[1]), PROP_ID(letags[1]), 0},
	};
	const SORTORDER_SET sort_set = {sort_count, 0, 0, deconst(sort_spec)};

	fprintf(stderr, "\e[7m*** Requesting %xh, sort_orders %u ***\e[0m\n", elist_tag, sort_count);
	unsigned int table_id = 0, row_count = 0;
	if (!exmdb_client::load_content_table(dir, CP_UTF8, folder_id, nullptr,
	    0, nullptr, sort_set.count > 0 ? &sort_set : nullptr,
	    &table_id, &row_count)) {
		fprintf(stderr, "LCT failed\n");
		return -1;
	}
	auto cl_0 = make_scope_exit([&]() { exmdb_client::unload_table(dir, table_id); });
	TARRAY_SET rowset{};
	if (!exmdb_client::query_table(dir, nullptr, CP_UTF8, table_id, &tagarr,
	    0, 25, &rowset)) {
		printf("QueryTable failed\n");
		return -1;
	}
	for (unsigned int i = 0; i < rowset.count; ++i) {
		auto row = *rowset.pparray[i];
		printf("row %u: {", i);
		for (unsigned int j = 0; j < row.count; ++j)
			printf("%xh,", row.ppropval[j].proptag);
		printf("}\n");
	}
	return rowset.count;
}

int main(int argc, const char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <maildir>\n", argv[0]);
		return EXIT_FAILURE;
	}

	exmdb_client_init(1, 0);
	exmdb_client_run(PKGSYSCONFDIR);

	auto dir = argv[1];
	uint64_t folder_id = PRIVATE_FID_CONTACTS;
	if (argc >= 3)
		folder_id = strtoull(argv[2], nullptr, 0);
	folder_id = rop_util_make_eid_ex(1, folder_id);

	uint32_t elist_tag = propid_elist(dir);
	int ret[8];
	auto tg2 = CHANGE_PROP_TYPE(elist_tag, static_cast<unsigned int>(PT_MV_LONG) | MV_INSTANCE);
	ret[5] = askfor(dir, folder_id, tg2, 0);
	ret[6] = askfor(dir, folder_id, tg2, 1);
	ret[7] = askfor(dir, folder_id, tg2, 2);
	auto tg0 = CHANGE_PROP_TYPE(elist_tag, PT_LONG);
	ret[0] = askfor(dir, folder_id, tg0, 0);
	ret[1] = askfor(dir, folder_id, tg0, 1);
	ret[2] = askfor(dir, folder_id, tg0, 2);
	auto tg1 = CHANGE_PROP_TYPE(elist_tag, PT_MV_LONG);
	ret[3] = askfor(dir, folder_id, tg1, 0);
	ret[4] = askfor(dir, folder_id, tg1, 1);
	if (askfor(dir, folder_id, tg1, 2) != -1)
		return EXIT_FAILURE;
	// the failing LCT also closed the connection and there's a repickup issue
	fprintf(stderr, "1 expected failure\n");
	for (auto v : ret)
		if (v < 0)
			return EXIT_FAILURE;
	fprintf(stderr, "Success\n");
	return EXIT_SUCCESS;
}
