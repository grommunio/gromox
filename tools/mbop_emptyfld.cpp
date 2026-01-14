// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022–2025 grommunio GmbH
// This file is part of Gromox.
#include <climits>
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
static mapitime_t g_cutoff_time;

static constexpr HXoption g_options_table[] = {
	{{}, 'M', HXTYPE_NONE, {}, {}, {}, 'M', "Exclude normal messages from deletion"},
	{{}, 'R', HXTYPE_NONE, {}, {}, {}, 'R', "Recurse into subfolders to delete messages"},
	{"delempty", 0, HXTYPE_NONE, {}, {}, {}, '1', "Delete subfolders which are empty"},
	{"nuke-folders", 0, HXTYPE_NONE, {}, {}, {}, '2', "Do not recurse but delete subfolders outright"},
	{{}, 'a', HXTYPE_NONE, {}, {}, {}, 'a', "Include associated messages in deletion"},
	{{}, 't', HXTYPE_STRING, {}, {}, {}, 't', "Messages need to be older than...", "TIMESPEC"},
	{"soft", 0, HXTYPE_NONE, {}, {}, {}, '3', "Soft-delete"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

static int generic_del(eid_t fid, const std::vector<eid_t> &chosen)
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

static ec_error_t do_contents(eid_t fid, unsigned int tbl_flags)
{
	std::vector<eid_t> chosen;
	static constexpr RESTRICTION_EXIST rst_a = {PR_LAST_MODIFICATION_TIME};
	RESTRICTION_PROPERTY rst_b = {RELOP_LE, PR_LAST_MODIFICATION_TIME,
		{PR_LAST_MODIFICATION_TIME, &g_cutoff_time}};
	RESTRICTION rst_c[2] = {{RES_EXIST, {deconst(&rst_a)}}, {RES_PROPERTY, {deconst(&rst_b)}}};
	RESTRICTION_AND_OR rst_d = {std::size(rst_c), deconst(rst_c)};
	RESTRICTION rst_e = {RES_AND, {deconst(&rst_d)}};
	auto err = select_contents_from_folder(fid, tbl_flags, &rst_e, chosen);
	if (err != ecSuccess) {
		mbop_fprintf(stderr, "load_contents %llxh failed\n", LLU{fid});
		return err;
	}
	return generic_del(fid, std::move(chosen)) == 0 ? ecSuccess : ecError;
}

static ec_error_t do_hierarchy(eid_t fid, uint32_t depth)
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
		if (ret != ecSuccess)
			return ret;
	}
	if (g_del_flags & DEL_ASSOCIATED) {
		auto ret = do_contents(fid, MAPI_ASSOCIATED);
		if (ret != ecSuccess)
			return ret;
	}
	if (!g_recurse)
		return ecSuccess;

	std::vector<eid_t> chosen_fids;
	auto err = select_hierarchy(fid, 0, chosen_fids);
	if (err != ecSuccess) {
		mbop_fprintf(stderr, "load_hierarchy %llxh failed\n", LLU{fid});
		return err;
	}
	for (auto sub_fid : chosen_fids) {
		err = do_hierarchy(sub_fid, depth + 1);
		if (err != ecSuccess)
			return err;
	}
	}

	if (depth == 0 || !g_delempty)
		return ecSuccess;
	static constexpr proptag_t ftags2[] = {PR_CONTENT_COUNT, PR_ASSOC_CONTENT_COUNT, PR_FOLDER_CHILD_COUNT};
	TPROPVAL_ARRAY props{};
	if (!exmdb_client->get_folder_properties(g_storedir, CP_ACP, fid, ftags2, &props)) {
		mbop_fprintf(stderr, "fid 0x%llx get_folder_props failed\n", LLU{fid});
		return ecRpcFailed;
	}
	auto p1 = props.get<const uint32_t>(PR_CONTENT_COUNT);
	auto p2 = props.get<const uint32_t>(PR_ASSOC_CONTENT_COUNT);
	auto p3 = props.get<const uint32_t>(PR_FOLDER_CHILD_COUNT);
	auto n1 = p1 != nullptr ? *p1 : 0;
	auto n2 = p2 != nullptr ? *p2 : 0;
	auto n3 = p3 != nullptr ? *p3 : 0;
	if (n1 != 0 || n2 != 0 || n3 != 0)
		return ecSuccess;
	BOOL b_result = false;
	if (!exmdb_client->delete_folder(g_storedir, CP_ACP, fid,
	    g_del_flags & DELETE_HARD_DELETE, &b_result)) {
		mbop_fprintf(stderr, "fid 0x%llx delete_folder RPC rejected/malformed\n", LLU{rop_util_get_gc_value(fid)});
		return ecRpcFailed;
	} else if (!b_result) {
		mbop_fprintf(stderr, "fid 0x%llx delete_folder unsuccessful (no permissions etc.)\n", LLU{rop_util_get_gc_value(fid)});
	} else {
		mbop_fprintf(stderr, "Folder 0x%llx: deleted due to --delempty\n", LLU{rop_util_get_gc_value(fid)});
	}
	return ecSuccess;
}

int main(int argc, char **argv)
{
	const char *g_time_str = nullptr;
	HXopt6_auto_result result;
	if (HX_getopt6(g_options_table, argc, argv, &result, HXOPT_USAGEONERR |
	    HXOPT_ITER_OA) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;
	for (int i = 0; i < result.nopts; ++i)
		switch (result.desc[i]->val) {
		case 'M': g_del_flags &= ~DEL_MESSAGES; break;
		case 'R': g_recurse = true; break;
		case '1': g_delempty = true; break;
		case '2': g_del_flags |= DEL_FOLDERS; break;
		case 'a': g_del_flags |= DEL_ASSOCIATED; break;
		case 't': g_time_str = result.oarg[i]; break;
		case '3': g_del_flags &= ~DELETE_HARD_DELETE; break;
		default: break;
		}

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
	for (int uidx = 0; uidx < result.nargs; ++uidx) {
		BOOL partial = false;
		auto eid = gi_lookup_eid_any_way(g_storedir, result.uarg[uidx]);
		if (eid == 0) {
			mbop_fprintf(stderr, "Not recognized/found: \"%s\"\n", result.uarg[uidx]);
			return EXIT_FAILURE;
		}
		if (g_cutoff_time != 0 || g_recurse) {
			/* Deletion via client */
			auto err = do_hierarchy(eid, 0);
			if (err != ecSuccess)
				return EXIT_FAILURE;
			continue;
		}
		uint32_t prev_delc, prev_fldc, curr_delc, curr_fldc;
		delcount(eid, &prev_delc, &prev_fldc);
		auto ok = exmdb_client->empty_folder(g_storedir, CP_UTF8, nullptr,
		          eid, g_del_flags, &partial);
		if (!ok) {
			mbop_fprintf(stderr, "empty_folder(%s) failed\n", result.uarg[uidx]);
			ret = EXIT_FAILURE;
		}
		delcount(eid, &curr_delc, &curr_fldc);
		if (partial)
			printf("Partial completion (e.g. essential permanent folders were not deleted)\n");
		printf("Folder %s: deleted %d message(s), deleted %d subfolder(s) plus messages\n",
			result.uarg[uidx], curr_delc - prev_delc, prev_fldc - curr_fldc);
		if (ret != EXIT_SUCCESS)
			break;
	}
	return ret;
}

}
