// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022–2025 grommunio GmbH
// This file is part of Gromox.
#include <vector>
#include <libHX/scope.hpp>
#include <gromox/mapidefs.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/rop_util.hpp>

/**
 * @fid:       Folder to start at
 * @tbl_flags: E.g. TBL_FLAG_ASSOCIATED
 * @rst:       Message filter
 * @chosen:    Output buffer for message IDs
 *
 * Obtain a list of message IDs in @fid.
 */
ec_error_t select_contents_from_folder(eid_t fid, unsigned int tbl_flags,
    const RESTRICTION *rst, std::vector<eid_t> &chosen) try
{
	uint32_t table_id = 0, row_count = 0;
	if (!exmdb_client->load_content_table(g_storedir, CP_ACP, fid, nullptr,
	    tbl_flags, rst, nullptr, &table_id, &row_count)) {
		mbop_fprintf(stderr, "fid 0x%llx load_content_table failed\n", LLU{rop_util_get_gc_value(fid)});
		return ecRpcFailed;
	}
	auto cl_0 = HX::make_scope_exit([&]() { exmdb_client->unload_table(g_storedir, table_id); });
	static constexpr proptag_t mtags[] = {PidTagMid};
	static constexpr PROPTAG_ARRAY mtaghdr = {std::size(mtags), deconst(mtags)};
	tarray_set rowset{};
	if (!exmdb_client->query_table(g_storedir, nullptr, CP_ACP, table_id,
	    &mtaghdr, 0, row_count, &rowset)) {
		mbop_fprintf(stderr, "fid 0x%llx query_table failed\n", LLU{rop_util_get_gc_value(fid)});
		return ecRpcFailed;
	}
	for (const auto &row : rowset) {
		auto mid = row.get<const eid_t>(PidTagMid);
		if (mid != nullptr)
			chosen.push_back(*mid);
	}
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ecServerOOM;
}

/**
 * @fid:       Folder to start at
 * @tbl_flags: E.g. TBL_FLAG_DEPTH to grab all subordinates at once
 * @chosen:    Output buffer (won't contain @fid)
 *
 * Obtain a list of subordinate folder IDs starting at @fid.
 */
ec_error_t select_hierarchy(eid_t fid, unsigned int tbl_flags,
    std::vector<eid_t> &chosen) try
{
	uint32_t table_id = 0, row_count = 0;
	if (!exmdb_client->load_hierarchy_table(g_storedir, fid,
	    nullptr, tbl_flags, nullptr, &table_id, &row_count)) {
		mbop_fprintf(stderr, "fid 0x%llx load_content_table failed\n", LLU{rop_util_get_gc_value(fid)});
		return ecRpcFailed;
	}
	auto cl_0 = HX::make_scope_exit([=]() { exmdb_client->unload_table(g_storedir, table_id); });
	static constexpr proptag_t ftags[] = {PidTagFolderId};
	static constexpr PROPTAG_ARRAY ftaghdr = {std::size(ftags), deconst(ftags)};
	tarray_set rowset{};
	if (!exmdb_client->query_table(g_storedir, nullptr, CP_ACP, table_id,
	    &ftaghdr, 0, row_count, &rowset)) {
		mbop_fprintf(stderr, "fid 0x%llx query_table failed\n", LLU{rop_util_get_gc_value(fid)});
		return ecRpcFailed;
	}
	exmdb_client->unload_table(g_storedir, table_id);
	for (const auto &row : rowset) {
		auto p = row.get<const eid_t>(PidTagFolderId);
		if (p != nullptr)
			chosen.emplace_back(*p);
	}
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ecServerOOM;
}
