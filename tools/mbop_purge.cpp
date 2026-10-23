// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023–2025 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <string>
#include <vector>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <gromox/authmgr.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include "genimport.hpp"
#include "mbop.hpp"

using namespace gromox;

namespace purgesoftdel {

static unsigned int g_recursive;
static const char *g_age_str;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'r', HXTYPE_NONE, &g_recursive, nullptr, nullptr, 0, "Process folders recursively"},
	{nullptr, 't', HXTYPE_STRING, &g_age_str, nullptr, nullptr, 0, "Messages need to be older than...", "TIMESPEC"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

int main(int argc, char **argv)
{
	HXopt6_auto_result result;
	if (HX_getopt6(g_options_table, argc, argv, &result,
	    HXOPT_USAGEONERR | HXOPT_ITER_OA) != HXOPT_ERR_SUCCESS ||
	    g_exit_after_optparse)
		return EXIT_PARAM;
	if (result.nargs == 0)
		mbop_fprintf(stderr, "mbop/purge: No folders specified, no action taken.\n");
	auto age = rop_util_unix_to_nttime(time(nullptr) - HX_strtoull_sec(znul(g_age_str), nullptr));
	for (int uidx = 0; uidx < result.nargs; ++uidx) {
		auto eid = gi_lookup_eid_any_way(g_storedir, result.uarg[uidx]);
		if (eid == 0) {
			mbop_fprintf(stderr, "Not recognized/found: \"%s\"\n", result.uarg[uidx]);
			return EXIT_FAILURE;
		}
		unsigned int flags = g_recursive ? DEL_FOLDERS : 0;
		uint32_t st_folders = 0, st_messages = 0;
		uint64_t sz_normal = 0, sz_fai = 0;
		auto ok = exmdb_client->purge_softdelete(g_storedir, nullptr,
		          eid, flags, age, &st_folders, &st_messages,
		          &sz_normal, &sz_fai);
		if (!ok) {
			mbop_fprintf(stderr, "purge_softdel %s failed\n", result.uarg[uidx]);
			return EXIT_FAILURE;
		}
		char nbuf[32], fbuf[32];
		HX_unit_size(nbuf, std::size(nbuf), sz_normal, 0, 0);
		HX_unit_size(fbuf, std::size(fbuf), sz_fai,    0, 0);
		printf("purge_softdelete: deleted %u messages, %u folders, reclaimed %sB (and %sB FAI)\n",
			static_cast<unsigned int>(st_messages),
			static_cast<unsigned int>(st_folders), nbuf, fbuf);
	}
	return EXIT_SUCCESS;
}

}

namespace cgkreset {

static constexpr HXoption g_options_table[] = {
	{{}, 'P', HXTYPE_NONE, {}, {}, {}, 0, "Purge PCL of foreign identifiers"},
	{{}, 'Z', HXTYPE_NONE, {}, {}, {}, 0, "Start with CN 0"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

int main(int argc, char **argv)
{
	unsigned int flags = CGKRESET_FOLDERS | CGKRESET_MESSAGES;
	HXopt6_auto_result result;

	if (HX_getopt6(g_options_table, argc, argv, &result, HXOPT_USAGEONERR |
	    HXOPT_ITER_OPTS) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;
	for (int i = 0; i < result.nopts; ++i)
		if (result.desc[i]->sh == 'Z')
			flags |= CGKRESET_ZERO_LASTCN;
	if (!exmdb_client->cgkreset(g_storedir, flags)) {
		mbop_fprintf(stderr, "cgkreset %s failed\n", g_storedir);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

}

namespace purgeperms {

static unsigned int g_dry_run;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'n', HXTYPE_NONE, &g_dry_run, nullptr, nullptr, 0, "Only list the entries"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

/* 1: user exists, 0: user is gone, -1: lookup failed */
static int user_exists(const std::string &name, std::map<std::string, int> &cache)
{
	auto it = cache.find(name);
	if (it != cache.end())
		return it->second;
	int ret = 1;
	if (str_isascii(name.c_str()) &&
	    !mysql_adaptor_get_user_ids(name.c_str(), nullptr, nullptr, nullptr)) {
		sql_meta_result mres;
		auto err = mysql_adaptor_meta(name.c_str(), WANTPRIV_METAONLY, mres);
		if (err == ENOENT)
			ret = strstr(mres.errstr.c_str(), "ambiguous") != nullptr ? 1 : 0;
		else if (err != 0)
			ret = -1;
	}
	cache.emplace(name, ret);
	return ret;
}

static int do_folder(eid_t fid, std::map<std::string, int> &cache, unsigned int &total)
{
	uint32_t table_id = 0, row_count = 0;
	if (!exmdb_client->load_permission_table(g_storedir, fid, 0,
	    &table_id, &row_count)) {
		mbop_fprintf(stderr, "fid 0x%llx load_permission_table failed\n", LLU{rop_util_get_gc_value(fid)});
		return EXIT_FAILURE;
	}
	static constexpr proptag_t tags[] = {PR_MEMBER_ID, PR_SMTP_ADDRESS};
	tarray_set rowset{};
	auto ok = exmdb_client->query_table(g_storedir, nullptr, CP_ACP,
	          table_id, tags, 0, row_count, &rowset);
	exmdb_client->unload_table(g_storedir, table_id);
	if (!ok) {
		mbop_fprintf(stderr, "fid 0x%llx query_table failed\n", LLU{rop_util_get_gc_value(fid)});
		return EXIT_FAILURE;
	}
	std::vector<PERMISSION_DATA> rows;
	std::vector<TAGGED_PROPVAL> vals;
	vals.reserve(rowset.count);
	for (const auto &row : rowset) {
		auto mid = row.get<const uint64_t>(PR_MEMBER_ID);
		auto name = row.get<const char>(PR_SMTP_ADDRESS);
		if (mid == nullptr || name == nullptr || *name == '\0' ||
		    static_cast<int64_t>(*mid) == MEMBER_ID_DEFAULT ||
		    static_cast<int64_t>(*mid) == MEMBER_ID_ANONYMOUS)
			continue;
		auto ex = user_exists(name, cache);
		if (ex < 0) {
			mbop_fprintf(stderr, "Could not look up \"%s\" in the user database\n", name);
			return EXIT_FAILURE;
		} else if (ex > 0) {
			continue;
		}
		printf("Folder 0x%llx: %s%s\n", LLU{rop_util_get_gc_value(fid)},
		       g_dry_run ? "" : "removing ", name);
		vals.push_back({PR_MEMBER_ID, deconst(mid)});
		rows.push_back({ROW_REMOVE, {1, &vals.back()}});
	}
	total += rows.size();
	if (g_dry_run || rows.empty())
		return EXIT_SUCCESS;
	if (!exmdb_client->update_folder_permission(g_storedir, fid, false,
	    rows.size(), rows.data())) {
		mbop_fprintf(stderr, "fid 0x%llx update_folder_permission failed\n", LLU{rop_util_get_gc_value(fid)});
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	HXopt6_auto_result result;
	if (HX_getopt6(g_options_table, argc, argv, &result,
	    HXOPT_USAGEONERR | HXOPT_ITER_OA) != HXOPT_ERR_SUCCESS ||
	    g_exit_after_optparse)
		return EXIT_PARAM;
	eid_t root(1, g_public_folder ? PUBLIC_FID_ROOT : PRIVATE_FID_ROOT);
	std::vector<eid_t> fids{root};
	auto err = select_hierarchy(root, TABLE_FLAG_DEPTH, fids);
	if (err != ecSuccess) {
		mbop_fprintf(stderr, "load_hierarchy failed: %s\n", mapi_strerror(err));
		return EXIT_FAILURE;
	}
	std::map<std::string, int> cache;
	unsigned int total = 0;
	for (auto fid : fids) {
		auto ret = do_folder(fid, cache, total);
		if (ret != EXIT_SUCCESS)
			return ret;
	}
	printf("%u permission entries of nonexistent users %s\n", total,
	       g_dry_run ? "found" : "removed");
	return EXIT_SUCCESS;
}

}
