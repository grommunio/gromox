// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/mapidefs.h>
#include <gromox/rop_util.hpp>
#include "genimport.hpp"
#include "mbop.hpp"

using namespace gromox;

namespace emptyfld {

static unsigned int g_del_flags = DEL_MESSAGES | DELETE_HARD_DELETE, g_recurse, g_delempty;
static char *g_time_str;
static mapitime_t g_cutoff_time;

static void opt_m(const struct HXoptcb *cb) { g_del_flags &= ~DEL_MESSAGES; }
static void opt_nuke(const struct HXoptcb *cb) { g_del_flags |= DEL_FOLDERS; }
static void opt_a(const struct HXoptcb *cb) { g_del_flags |= DEL_ASSOCIATED; }
static void opt_s(const struct HXoptcb *cb) { g_del_flags &= ~DELETE_HARD_DELETE; }

static constexpr HXoption g_options_table[] = {
	{nullptr, 'M', HXTYPE_NONE, {}, {}, opt_m, 0, "Exclude normal messages from deletion"},
	{nullptr, 'R', HXTYPE_NONE, &g_recurse, {}, {}, 0, "Recurse into subfolders to delete messages"},
	{"delempty", 0, HXTYPE_NONE, &g_delempty, {}, {}, 0, "Delete subfolders which are empty"},
	{"nuke-folders", 0, HXTYPE_NONE, {}, {}, opt_nuke, 0, "Do not recurse but delete subfolders outright"},
	{nullptr, 'a', HXTYPE_NONE, {}, {}, opt_a, 0, "Include associated messages in deletion"},
	{nullptr, 't', HXTYPE_STRING, &g_time_str, {}, {}, 0, "Messages need to be older than...", "TIMESPEC"},
	{"soft",    0, HXTYPE_NONE, {}, {}, opt_s, 0, "Soft-delete (experimental)"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

static int generic_del(eid_t fid, const std::vector<uint64_t> &chosen)
{
	BOOL partial_complete = false;
	EID_ARRAY ea;
	ea.count = chosen.size();
	ea.pids  = deconst(chosen.data());
	if (!exmdb_client->delete_messages(g_storedir, CP_ACP, nullptr, fid,
	    &ea, false, &partial_complete)) {
		mbop_fprintf(stderr, "fid 0x%llx delete_messages failed\n", LLU{rop_util_get_gc_value(fid)});
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int select_mids_by_time(eid_t fid, unsigned int tbl_flags,
    std::vector<uint64_t> &chosen)
{
	uint32_t table_id = 0, row_count = 0;
	static constexpr RESTRICTION_EXIST rst_a = {PR_LAST_MODIFICATION_TIME};
	RESTRICTION_PROPERTY rst_b = {RELOP_LE, PR_LAST_MODIFICATION_TIME,
		{PR_LAST_MODIFICATION_TIME, &g_cutoff_time}};
	RESTRICTION rst_c[2] = {{RES_EXIST, {deconst(&rst_a)}}, {RES_PROPERTY, {deconst(&rst_b)}}};
	RESTRICTION_AND_OR rst_d = {std::size(rst_c), deconst(rst_c)};
	RESTRICTION rst_e = {RES_AND, {deconst(&rst_d)}};
	if (!exmdb_client->load_content_table(g_storedir, CP_ACP, fid, nullptr,
	    tbl_flags, &rst_e, nullptr, &table_id, &row_count)) {
		mbop_fprintf(stderr, "fid 0x%llx load_content_table failed\n", LLU{rop_util_get_gc_value(fid)});
		return EXIT_FAILURE;
	}
	auto cl_0 = HX::make_scope_exit([&]() { exmdb_client->unload_table(g_storedir, table_id); });
	static constexpr uint32_t mtags[] = {PidTagMid};
	static constexpr PROPTAG_ARRAY mtaghdr = {std::size(mtags), deconst(mtags)};
	tarray_set rowset{};
	if (!exmdb_client->query_table(g_storedir, nullptr, CP_ACP, table_id,
	    &mtaghdr, 0, row_count, &rowset)) {
		mbop_fprintf(stderr, "fid 0x%llx query_table failed\n", LLU{rop_util_get_gc_value(fid)});
		return EXIT_FAILURE;
	}
	for (const auto &row : rowset) {
		auto mid = row.get<const eid_t>(PidTagMid);
		if (mid != nullptr)
			chosen.push_back(*mid);
	}
	return EXIT_SUCCESS;
}

static int do_contents(eid_t fid, unsigned int tbl_flags)
{
	std::vector<uint64_t> chosen;
	auto ret = select_mids_by_time(fid, tbl_flags, chosen);
	if (ret != EXIT_SUCCESS)
		return ret;
	return generic_del(fid, std::move(chosen));
}

static int do_hierarchy(eid_t fid, uint32_t depth)
{
	{
	uint32_t prev_delc, prev_fldc;
	delcount(fid, &prev_delc, &prev_fldc);
	auto cl_0 = HX::make_scope_exit([&]() {
		uint32_t curr_delc, curr_fldc;
		delcount(fid, &curr_delc, &curr_fldc);
		printf("Folder 0x%llx: deleted %d message(s)\n", LLU{rop_util_get_gc_value(fid)}, curr_delc - prev_delc);
	});
	if (g_del_flags & DEL_MESSAGES) {
		auto ret = do_contents(fid, 0);
		if (ret != EXIT_SUCCESS)
			return ret;
	}
	if (g_del_flags & DEL_ASSOCIATED) {
		auto ret = do_contents(fid, MAPI_ASSOCIATED);
		if (ret != EXIT_SUCCESS)
			return ret;
	}
	if (!g_recurse)
		return EXIT_SUCCESS;

	uint32_t table_id = 0, row_count = 0;
	if (!exmdb_client->load_hierarchy_table(g_storedir, fid,
	    nullptr, 0, nullptr, &table_id, &row_count)) {
		mbop_fprintf(stderr, "fid 0x%llx load_content_table failed\n", LLU{rop_util_get_gc_value(fid)});
		return EXIT_FAILURE;
	}
	auto cl_1 = HX::make_scope_exit([=]() { exmdb_client->unload_table(g_storedir, table_id); });
	static constexpr uint32_t ftags[] = {PidTagFolderId};
	static constexpr PROPTAG_ARRAY ftaghdr = {std::size(ftags), deconst(ftags)};
	tarray_set rowset{};
	if (!exmdb_client->query_table(g_storedir, nullptr, CP_ACP, table_id,
	    &ftaghdr, 0, row_count, &rowset)) {
		mbop_fprintf(stderr, "fid 0x%llx query_table failed\n", LLU{rop_util_get_gc_value(fid)});
		return EXIT_FAILURE;
	}
	exmdb_client->unload_table(g_storedir, table_id);
	for (const auto &row : rowset) {
		auto p = row.get<const eid_t>(PidTagFolderId);
		if (p != nullptr)
			do_hierarchy(*p, depth + 1);
	}
	}

	if (depth == 0 || !g_delempty)
		return EXIT_SUCCESS;
	static constexpr uint32_t ftags2[] = {PR_CONTENT_COUNT, PR_ASSOC_CONTENT_COUNT, PR_FOLDER_CHILD_COUNT};
	static constexpr PROPTAG_ARRAY ftaghdr2 = {std::size(ftags2), deconst(ftags2)};
	TPROPVAL_ARRAY props{};
	if (!exmdb_client->get_folder_properties(g_storedir, CP_ACP, fid, &ftaghdr2, &props)) {
		mbop_fprintf(stderr, "fid 0x%llx get_folder_props failed\n", LLU{fid});
		return EXIT_FAILURE;
	}
	auto p1 = props.get<const uint32_t>(PR_CONTENT_COUNT);
	auto p2 = props.get<const uint32_t>(PR_ASSOC_CONTENT_COUNT);
	auto p3 = props.get<const uint32_t>(PR_FOLDER_CHILD_COUNT);
	auto n1 = p1 != nullptr ? *p1 : 0;
	auto n2 = p2 != nullptr ? *p2 : 0;
	auto n3 = p3 != nullptr ? *p3 : 0;
	if (n1 != 0 || n2 != 0 || n3 != 0)
		return EXIT_SUCCESS;
	BOOL b_result = false;
	if (!exmdb_client->delete_folder(g_storedir, CP_ACP, fid,
	    g_del_flags & DELETE_HARD_DELETE, &b_result)) {
		mbop_fprintf(stderr, "fid 0x%llx delete_folder RPC rejected/malformed\n", LLU{rop_util_get_gc_value(fid)});
		return EXIT_FAILURE;
	} else if (!b_result) {
		mbop_fprintf(stderr, "fid 0x%llx delete_folder unsuccessful (no permissions etc.)\n", LLU{rop_util_get_gc_value(fid)});
	} else {
		mbop_fprintf(stderr, "Folder 0x%llx: deleted due to --delempty\n", LLU{rop_util_get_gc_value(fid)});
	}
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	if (HX_getopt5(g_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;
	auto cl_0 = HX::make_scope_exit([=]() { HX_zvecfree(argv); });
	if (g_del_flags & DEL_FOLDERS && g_recurse) {
		mbop_fprintf(stderr, "Combining -R and --nuke-folders is unreasonable: when you nuke folders, you cannot recurse into them anymore.\n");
		return EXIT_FAILURE;
	} else if (g_delempty && !g_recurse) {
		mbop_fprintf(stderr, "--delempty requires -R\n");
		return EXIT_FAILURE;
	}
	if (g_time_str != nullptr) {
		char *end = nullptr;
		auto t = HX_strtoull_sec(g_time_str, &end);
		if (t == ULLONG_MAX && errno == ERANGE) {
			mbop_fprintf(stderr, "Timespec \"%s\" is too damn big\n", g_time_str);
			return EXIT_FAILURE;
		} else if (end != nullptr && *end != '\0') {
			mbop_fprintf(stderr, "Timespec \"%s\" not fully understood (error at: \"%s\")\n",
				g_time_str, end);
			return EXIT_FAILURE;
		}
		g_cutoff_time = rop_util_unix_to_nttime(time(nullptr) - t);
		if (g_del_flags & DEL_FOLDERS) {
			mbop_fprintf(stderr, "Combining -t and --nuke-folders is unreasonable: when you delete folders, it may delete messages therein which are younger than -t.\n");
			return EXIT_FAILURE;
		}
	}

	int ret = EXIT_SUCCESS;
	while (*++argv != nullptr) {
		BOOL partial = false;
		eid_t eid = gi_lookup_eid_by_name(g_storedir, *argv);
		if (eid == 0) {
			mbop_fprintf(stderr, "Not recognized/found: \"%s\"\n", *argv);
			return EXIT_FAILURE;
		}
		if (g_cutoff_time != 0 || g_recurse) {
			/* Deletion via client */
			ret = do_hierarchy(eid, 0);
			if (ret != EXIT_SUCCESS)
				return ret;
			continue;
		}
		uint32_t prev_delc, prev_fldc, curr_delc, curr_fldc;
		delcount(eid, &prev_delc, &prev_fldc);
		auto ok = exmdb_client->empty_folder(g_storedir, CP_UTF8, nullptr,
		          eid, g_del_flags, &partial);
		if (!ok) {
			mbop_fprintf(stderr, "empty_folder(%s) failed\n", *argv);
			ret = EXIT_FAILURE;
		}
		delcount(eid, &curr_delc, &curr_fldc);
		if (partial)
			printf("Partial completion (e.g. essential permanent folders were not deleted)\n");
		printf("Folder %s: deleted %d message(s), deleted %d subfolder(s) plus messages\n",
			*argv, curr_delc - prev_delc, prev_fldc - curr_fldc);
		if (ret != EXIT_SUCCESS)
			break;
	}
	return ret;
}

}
