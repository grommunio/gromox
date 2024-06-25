// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2024 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <vector>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "genimport.hpp"

using namespace std::string_literals;
using namespace gromox;
using LLU = unsigned long long;
namespace exmdb_client = exmdb_client_remote;

static constexpr HXoption empty_options_table[] = {
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

namespace delmsg {

static char *g_folderstr;
static eid_t g_folderid;
static unsigned int g_soft;

static constexpr HXoption g_options_table[] = {
	{nullptr, 'f', HXTYPE_STRING, &g_folderstr, nullptr, nullptr, 0, "Folder ID"},
	{"soft", 0, HXTYPE_NONE, &g_soft, nullptr, nullptr, 0, "Soft-delete"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static int help()
{
	fprintf(stderr, "Usage: gromox-mbop -u a@b.de delmsg -f folder_id message_id[,...]\n");
	return EXIT_FAILURE;
}

}

static void delcount(eid_t fid, uint32_t *delc, uint32_t *fldc)
{
	static constexpr uint32_t tags[] = {PR_DELETED_COUNT_TOTAL, PR_FOLDER_CHILD_COUNT};
	static constexpr PROPTAG_ARRAY taghdr = {std::size(tags), deconst(tags)};
	TPROPVAL_ARRAY props;
	*delc = *fldc = 0;
	if (!exmdb_client::get_folder_properties(g_storedir, CP_ACP, fid,
	    &taghdr, &props)) {
		fprintf(stderr, "delcount: get_folder_properties failed\n");
		return;
	}
	auto c = props.get<const uint32_t>(tags[0]);
	*delc = c != nullptr ? *c : 0;
	c = props.get<const uint32_t>(tags[1]);
	*fldc = c != nullptr ? *c : 0;
}

namespace delmsg {

static int main(int argc, char **argv)
{
	if (HX_getopt5(g_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	auto cl_0 = make_scope_exit([=]() { HX_zvecfree(argv); });
	if (g_folderstr != nullptr) {
		char *end = nullptr;
		uint64_t fid = strtoul(g_folderstr, &end, 0);
		if (end == g_folderstr || *end != '\0')
			g_folderid = gi_lookup_eid_by_name(g_storedir, g_folderstr);
		else
			g_folderid = rop_util_make_eid_ex(1, fid);
	}
	if (rop_util_get_gc_value(g_folderid) == 0)
		return help();
	std::vector<uint64_t> eids;
	while (*++argv != nullptr) {
		uint64_t id = strtoull(*argv, nullptr, 0);
		eid_t eid = id == 0 ? gi_lookup_eid_by_name(g_storedir, *argv) :
		            rop_util_make_eid_ex(1, id);
		if (eid == 0) {
			fprintf(stderr, "Not recognized/found: \"%s\"\n", *argv);
			return EXIT_FAILURE;
		}
		eids.push_back(eid);
	}
	EID_ARRAY ea;
	ea.count = eids.size();
	ea.pids = eids.data();
	BOOL partial = false;
	uint32_t prev_delc, prev_fldc, curr_delc, curr_fldc;
	delcount(g_folderid, &prev_delc, &prev_fldc);
	if (!exmdb_client::delete_messages(g_storedir, CP_UTF8, nullptr,
	    g_folderid, &ea, !g_soft, &partial)) {
		printf("RPC was rejected.\n");
		return EXIT_FAILURE;
	}
	delcount(g_folderid, &curr_delc, &curr_fldc);
	if (partial)
		printf("Partial completion\n");
	printf("%d messages deleted\n", curr_delc - prev_delc);
	return EXIT_SUCCESS;
}

} /* namespace delmsg */

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
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static int generic_del(eid_t fid, const std::vector<uint64_t> &chosen)
{
	BOOL partial_complete = false;
	EID_ARRAY ea;
	ea.count = chosen.size();
	ea.pids  = deconst(chosen.data());
	if (!exmdb_client::delete_messages(g_storedir, CP_ACP, nullptr, fid,
	    &ea, false, &partial_complete)) {
		fprintf(stderr, "fid 0x%llx delete_messages failed\n", LLU{rop_util_get_gc_value(fid)});
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
	if (!exmdb_client::load_content_table(g_storedir, CP_ACP, fid, nullptr,
	    tbl_flags, &rst_e, nullptr, &table_id, &row_count)) {
		fprintf(stderr, "fid 0x%llx load_content_table failed\n", LLU{rop_util_get_gc_value(fid)});
		return EXIT_FAILURE;
	}
	auto cl_0 = make_scope_exit([&]() { exmdb_client::unload_table(g_storedir, table_id); });
	static constexpr uint32_t mtags[] = {PidTagMid};
	static constexpr PROPTAG_ARRAY mtaghdr = {std::size(mtags), deconst(mtags)};
	tarray_set rowset{};
	if (!exmdb_client::query_table(g_storedir, nullptr, CP_ACP, table_id,
	    &mtaghdr, 0, row_count, &rowset)) {
		fprintf(stderr, "fid 0x%llx query_table failed\n", LLU{rop_util_get_gc_value(fid)});
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
	auto cl_0 = make_scope_exit([&]() {
		uint32_t curr_delc, curr_fldc;
		delcount(fid, &curr_delc, &curr_fldc);
		printf("Folder 0x%llx: deleted %d messages\n", LLU{rop_util_get_gc_value(fid)}, curr_delc - prev_delc);
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
	if (!exmdb_client::load_hierarchy_table(g_storedir, fid,
	    nullptr, 0, nullptr, &table_id, &row_count)) {
		fprintf(stderr, "fid 0x%llx load_content_table failed\n", LLU{rop_util_get_gc_value(fid)});
		return EXIT_FAILURE;
	}
	auto cl_1 = make_scope_exit([=]() { exmdb_client::unload_table(g_storedir, table_id); });
	static constexpr uint32_t ftags[] = {PidTagFolderId};
	static constexpr PROPTAG_ARRAY ftaghdr = {std::size(ftags), deconst(ftags)};
	tarray_set rowset{};
	if (!exmdb_client::query_table(g_storedir, nullptr, CP_ACP, table_id,
	    &ftaghdr, 0, row_count, &rowset)) {
		fprintf(stderr, "fid 0x%llx query_table failed\n", LLU{rop_util_get_gc_value(fid)});
		return EXIT_FAILURE;
	}
	exmdb_client::unload_table(g_storedir, table_id);
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
	if (!exmdb_client::get_folder_properties(g_storedir, CP_ACP, fid, &ftaghdr2, &props)) {
		fprintf(stderr, "fid 0x%llx get_folder_props failed\n", LLU{fid});
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
	if (!exmdb_client::delete_folder(g_storedir, CP_ACP, fid,
	    g_del_flags & DELETE_HARD_DELETE, &b_result)) {
		fprintf(stderr, "fid 0x%llx delete_folder RPC rejected/malformed\n", LLU{rop_util_get_gc_value(fid)});
		return EXIT_FAILURE;
	} else if (!b_result) {
		fprintf(stderr, "fid 0x%llx delete_folder unsuccessful (no permissions etc.)\n", LLU{rop_util_get_gc_value(fid)});
	} else {
		fprintf(stderr, "Folder 0x%llx: deleted due to --delempty\n", LLU{rop_util_get_gc_value(fid)});
	}
	return EXIT_SUCCESS;
}

static int main(int argc, char **argv)
{
	if (HX_getopt5(g_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	auto cl_0 = make_scope_exit([=]() { HX_zvecfree(argv); });
	if (g_del_flags & DEL_FOLDERS && g_recurse) {
		fprintf(stderr, "Combining -R and --nuke-folders is unreasonable: when you nuke folders, you cannot recurse into them anymore.\n");
		return EXIT_FAILURE;
	} else if (g_delempty && !g_recurse) {
		fprintf(stderr, "--delempty requires -R\n");
		return EXIT_FAILURE;
	}
	if (g_time_str != nullptr) {
		char *end = nullptr;
		auto t = HX_strtoull_sec(g_time_str, &end);
		if (t == ULLONG_MAX && errno == ERANGE) {
			fprintf(stderr, "Timespec \"%s\" is too damn big\n", g_time_str);
			return EXIT_FAILURE;
		} else if (end != nullptr && *end != '\0') {
			fprintf(stderr, "Timespec \"%s\" not fully understood (error at: \"%s\")\n",
				g_time_str, end);
			return EXIT_FAILURE;
		}
		g_cutoff_time = rop_util_unix_to_nttime(time(nullptr) - t);
		if (g_del_flags & DEL_FOLDERS) {
			fprintf(stderr, "Combining -t and --nuke-folders is unreasonable: when you delete folders, it may delete messages therein which are younger than -t.\n");
			return EXIT_FAILURE;
		}
	}

	int ret = EXIT_SUCCESS;
	while (*++argv != nullptr) {
		BOOL partial = false;
		uint64_t id = strtoull(*argv, nullptr, 0);
		eid_t eid = id == 0 ? gi_lookup_eid_by_name(g_storedir, *argv) :
		            rop_util_make_eid_ex(1, id);
		if (eid == 0) {
			fprintf(stderr, "Not recognized/found: \"%s\"\n", *argv);
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
		auto ok = exmdb_client::empty_folder(g_storedir, CP_UTF8, nullptr,
		          eid, g_del_flags, &partial);
		if (!ok) {
			fprintf(stderr, "empty_folder(%s) failed\n", *argv);
			ret = EXIT_FAILURE;
		}
		delcount(eid, &curr_delc, &curr_fldc);
		if (partial)
			printf("Partial completion (e.g. essential permanent folders were not deleted)\n");
		printf("Folder %s: deleted %d messages, deleted %d subfolders plus messages\n",
			*argv, curr_delc - prev_delc, prev_fldc - curr_fldc);
		if (ret != EXIT_SUCCESS)
			break;
	}
	return ret;
}

}

namespace purgesoftdel {

static unsigned int g_recursive;
static const char *g_age_str;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'r', HXTYPE_NONE, &g_recursive, nullptr, nullptr, 0, "Process folders recursively"},
	{nullptr, 't', HXTYPE_STRING, &g_age_str, nullptr, nullptr, 0, "Messages need to be older than...", "TIMESPEC"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static int main(int argc, char **argv)
{
	if (HX_getopt5(g_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	auto cl_0 = make_scope_exit([=]() { HX_zvecfree(argv); });
	if (argc < 2)
		fprintf(stderr, "mbop/purge: No folders specified, no action taken.\n");
	auto age = rop_util_unix_to_nttime(time(nullptr) - HX_strtoull_sec(znul(g_age_str), nullptr));
	while (*++argv != nullptr) {
		uint64_t id = strtoull(*argv, nullptr, 0);
		eid_t eid = id == 0 ? gi_lookup_eid_by_name(g_storedir, *argv) :
		            rop_util_make_eid_ex(1, id);
		if (eid == 0) {
			fprintf(stderr, "Not recognized/found: \"%s\"\n", *argv);
			return EXIT_FAILURE;
		}
		unsigned int flags = g_recursive ? DEL_FOLDERS : 0;
		auto ok = exmdb_client::purge_softdelete(g_storedir, nullptr,
		          eid, flags, age);
		if (!ok) {
			fprintf(stderr, "purge_softdel %s failed\n", *argv);
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

}

namespace set_locale {

static const char *g_language;
static unsigned int g_verbose;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'l', HXTYPE_STRING, &g_language, {}, {}, 0, "XPG/POSIX-style locale code (e.g. ja_JP)", "CODE"},
	{nullptr, 'v', HXTYPE_NONE, &g_verbose, {}, {}, 0, "Verbose mode"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};
static std::vector<static_module> g_dfl_svc_plugins =
	{{"libgxs_mysql_adaptor.so", SVC_mysql_adaptor}};

static int main(int argc, char **argv)
{
	if (HX_getopt5(g_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	auto cl_0a = make_scope_exit([=]() { HX_zvecfree(argv); });
	if (g_language == nullptr) {
		fprintf(stderr, "You need to specify the -l option\n");
		return EXIT_FAILURE;
	}
	textmaps_init();
	service_init({nullptr, g_dfl_svc_plugins, 1});
	auto cl_0 = make_scope_exit(service_stop);
	if (service_run_early() != 0 || service_run() != 0) {
		fprintf(stderr, "service_run: failed\n");
		return EXIT_FAILURE;
	}
	decltype(mysql_adaptor_set_user_lang) *sul;
	sul = reinterpret_cast<decltype(sul)>(service_query("set_user_lang", "system", typeid(*sul)));
	if (sul == nullptr) {
		fprintf(stderr, "no set_user_lang function in mysql_adaptor\n");
		return EXIT_FAILURE;
	}
	auto cl_1 = make_scope_exit([]() { service_release("set_user_lang", "system"); });
	if (!sul(g_dstuser.c_str(), g_language)) {
		fprintf(stderr, "Update of UI language rejected\n");
		return EXIT_FAILURE;
	}

	auto lang = folder_namedb_resolve(g_language);
	if (lang == nullptr) {
		fprintf(stderr, "No folder name translations for locale \"%s\" available.\n", g_language);
		return EXIT_SUCCESS;
	}
	unsigned int start_gcv = g_public_folder ? PUBLIC_FID_ROOT : PRIVATE_FID_ROOT;
	unsigned int end_gcv   = g_public_folder ? PUBLIC_FID_CUSTOM : PRIVATE_FID_CUSTOM;
	for (unsigned int gcv = start_gcv; gcv < end_gcv; ++gcv) {
		auto new_name = folder_namedb_get(lang, gcv);
		if (new_name == nullptr)
			continue;
		auto folder_id = rop_util_make_eid_ex(1, gcv);
		if (g_verbose) {
			static constexpr uint32_t tags[] = {PR_DISPLAY_NAME};
			static constexpr PROPTAG_ARRAY taghdr = {std::size(tags), deconst(tags)};
			TPROPVAL_ARRAY props{};
			if (!exmdb_client::get_folder_properties(g_storedir,
			    CP_ACP, folder_id, &taghdr, &props)) {
				fprintf(stderr, "get_folder_props failed\n");
				return EXIT_FAILURE;
			}
			auto orig_name = props.get<const char>(PR_DISPLAY_NAME);
			printf("[0x%02x] %s -> %s\n", gcv, znul(orig_name), new_name);
		}
		TAGGED_PROPVAL tp = {PR_DISPLAY_NAME, deconst(new_name)};
		const TPROPVAL_ARRAY new_props = {1, &tp};
		PROBLEM_ARRAY probs{};
		if (!exmdb_client::set_folder_properties(g_storedir, CP_ACP,
		    folder_id, &new_props, &probs)) {
			fprintf(stderr, "set_folder_props failed\n");
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

}

namespace global {

static char *g_arg_username, *g_arg_userdir;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'd', HXTYPE_STRING, &g_arg_userdir, nullptr, nullptr, 0, "Directory of the mailbox", "DIR"},
	{nullptr, 'u', HXTYPE_STRING, &g_arg_username, nullptr, nullptr, 0, "Username of store to import to", "EMAILADDR"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static int help()
{
	fprintf(stderr, "Usage: gromox-mbop [global-options] command [command-options] [command-args...]\n");
	fprintf(stderr, "Global options:\n");
	fprintf(stderr, "\t-?                           Global help (this text)\n");
	fprintf(stderr, "\t-u emailaddr/-d directory    Name of/path to mailbox\n");
	fprintf(stderr, "Commands:\n\tclear-photo clear-profile clear-rwz delmsg "
		"emptyfld get-photo get-websettings get-websettings-persistent "
		"get-websettings-recipients "
		"purge-datafiles purge-softdelete recalc-sizes set-locale "
		"set-photo set-websettings set-websettings-persistent "
		"set-websettings-recipients unload vacuum\n");
	fprintf(stderr, "Command options:\n");
	fprintf(stderr, "\t-?                           Call up option help for subcommand\n");
	return EXIT_FAILURE;
}

} /* namespace global */

namespace simple_rpc {

static constexpr HXoption g_options_table[] = {
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static inline uint64_t inul(const uint64_t *v)
{
	return v != nullptr ? *v : 0;
}

static bool recalc_sizes(const char *dir)
{
	static constexpr uint32_t tags[] = {
		PR_MESSAGE_SIZE_EXTENDED, PR_NORMAL_MESSAGE_SIZE_EXTENDED,
		PR_ASSOC_MESSAGE_SIZE_EXTENDED
	};
	static constexpr PROPTAG_ARRAY tags1 = {std::size(tags), deconst(tags)};
	TPROPVAL_ARRAY vals;
	auto ok = exmdb_client::get_store_properties(dir, CP_ACP, &tags1, &vals);
	if (!ok)
		return false;
	using LLU = unsigned long long;
	printf("Old: %llu bytes (%llu normal, %llu FAI)\n",
	       LLU{inul(vals.get<uint64_t>(tags[0]))},
	       LLU{inul(vals.get<uint64_t>(tags[1]))},
	       LLU{inul(vals.get<uint64_t>(tags[2]))});
	ok = exmdb_client::recalc_store_size(g_storedir, 0);
	if (!ok)
		return false;
	ok = exmdb_client::get_store_properties(g_storedir, CP_ACP, &tags1, &vals);
	if (!ok)
		return false;
	printf("New: %llu bytes (%llu normal, %llu FAI)\n",
		LLU{inul(vals.get<uint64_t>(tags[0]))},
		LLU{inul(vals.get<uint64_t>(tags[1]))},
		LLU{inul(vals.get<uint64_t>(tags[2]))});
	return true;
}

static int main(int argc, char **argv)
{
	bool ok = false;
	if (HX_getopt5(g_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	auto cl_0 = make_scope_exit([=]() { HX_zvecfree(argv); });
	if (strcmp(argv[0], "purge-datafiles") == 0)
		ok = exmdb_client::purge_datafiles(g_storedir);
	else if (strcmp(argv[0], "unload") == 0)
		ok = exmdb_client::unload_store(g_storedir);
	else if (strcmp(argv[0], "vacuum") == 0)
		ok = exmdb_client::vacuum(g_storedir);
	else if (strcmp(argv[0], "recalc-sizes") == 0)
		ok = recalc_sizes(g_storedir);
	else
		return -EINVAL;
	if (!ok) {
		fprintf(stderr, "%s: the operation failed\n", argv[0]);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

}

static errno_t resolvename(const GUID &guid, const char *name, bool create,
    uint16_t *out)
{
	const PROPERTY_NAME xn = {MNID_STRING, guid, 0, deconst(name)};
	const PROPNAME_ARRAY name_req = {1, deconst(&xn)};
	PROPID_ARRAY name_rsp{};
	if (!exmdb_client::get_named_propids(g_storedir, create, &name_req, &name_rsp))
		return EINVAL;
	if (name_rsp.count != name_req.count)
		return EINVAL;
	if (name_rsp.ppropid[0] == 0)
		return ENOENT;
	*out = name_rsp.ppropid[0];
	return 0;
}

static errno_t delstoreprop(int argc, char **argv, const GUID &guid, const char *name)
{
	if (HX_getopt5(empty_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	auto cl_0a = make_scope_exit([=]() { HX_zvecfree(argv); });

	uint16_t propid = 0;
	auto err = resolvename(guid, name, false, &propid);
	if (err == ENOENT)
		return 0;
	else if (err != 0)
		return err;
	uint32_t proptag = PROP_TAG(PT_BINARY, propid);
	const PROPTAG_ARRAY tags = {1, &proptag};
	if (!exmdb_client::remove_store_properties(g_storedir, &tags))
		return EINVAL;
	if (strcmp(name, "zcore_profsect") == 0)
		unlink((g_storedir + "/config/zarafa.dat"s).c_str());
	else if (strcmp(name, "photo") == 0)
		unlink((g_storedir + "/config/portrait.jpg"s).c_str());
	return 0;
}

static errno_t showstoreprop(uint32_t proptag)
{
	const PROPTAG_ARRAY tags = {1, &proptag};
	TPROPVAL_ARRAY vals{};
	if (!exmdb_client::get_store_properties(g_storedir, CP_ACP, &tags, &vals))
		return EINVAL;
	switch (PROP_TYPE(proptag)) {
	case PT_BINARY: {
		auto bv = vals.get<const BINARY>(proptag);
		if (bv == nullptr) {
			if (isatty(STDERR_FILENO))
				fprintf(stderr, "Property is unset\n");
			return 0;
		}
		if (isatty(STDOUT_FILENO) && isatty(STDERR_FILENO))
			fprintf(stderr, "[%u bytes of binary data]\n", bv->cb);
		if (!isatty(STDOUT_FILENO))
			write(STDOUT_FILENO, bv->pc, bv->cb);
		return 0;
	}
	case PT_STRING8:
	case PT_UNICODE: {
		auto str = vals.get<const char>(proptag);
		if (str != nullptr)
			fputs(str, stdout);
		return 0;
	}
	default:
		fprintf(stderr, "No printer implemented for 0x%x\n", proptag);
		return EINVAL;
	}
}

static errno_t showstoreprop(int argc, char **argv, const GUID guid,
    const char *name, uint16_t proptype)
{
	if (HX_getopt5(empty_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	auto cl_0a = make_scope_exit([=]() { HX_zvecfree(argv); });

	uint16_t propid = 0;
	auto err = resolvename(guid, name, false, &propid);
	if (err == ENOENT)
		return 0;
	else if (err != 0)
		return err;
	return showstoreprop(PROP_TAG(proptype, propid));
}

static errno_t setstoreprop(uint32_t proptag)
{
	size_t slurp_len = 0;
	std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_fd(STDIN_FILENO, &slurp_len));
	if (slurp_data == nullptr) {
		fprintf(stderr, "Outta memory\n");
		return ENOMEM;
	}
	BINARY bv;
	TAGGED_PROPVAL pv = {proptag};
	switch (PROP_TYPE(proptag)) {
	case PT_BINARY:
		bv.cb = slurp_len;
		bv.pv = slurp_data.get();
		pv.pvalue = &bv;
		break;
	case PT_STRING8:
	case PT_UNICODE:
		pv.pvalue = slurp_data.get();
		break;
	default:
		return EINVAL;
	}
	const TPROPVAL_ARRAY tprop_arr = {1, deconst(&pv)};
	PROBLEM_ARRAY prob{};
	if (!exmdb_client::set_store_properties(g_storedir, CP_ACP, &tprop_arr, &prob)) {
		mlog(LV_ERR, "set_store_prop RPC unsuccessful");
		return EIO;
	} else if (prob.count > 0) {
		mlog(LV_ERR, "set_store_prop action unsuccessful / property rejected");
		return EIO;
	}
	return 0;
}

static errno_t setstoreprop(int argc, char **argv, const GUID guid,
    const char *name, uint16_t proptype)
{
	if (HX_getopt5(empty_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	auto cl_0a = make_scope_exit([=]() { HX_zvecfree(argv); });

	uint16_t propid = 0;
	auto err = resolvename(guid, name, true, &propid);
	if (err == ENOENT) {
		fprintf(stderr, "namedprop %s not found\n", name);
		return EIO;
	} else if (err != 0) {
		fprintf(stderr, "%s\n", strerror(-err));
		return err;
	}
	return setstoreprop(PROP_TAG(proptype, propid));
}

static errno_t clear_rwz()
{
	static const eid_t inbox = rop_util_make_eid_ex(1, PRIVATE_FID_INBOX);
	static constexpr RESTRICTION_EXIST rst_a = {PR_MESSAGE_CLASS};
	static constexpr RESTRICTION_CONTENT rst_b = {FL_IGNORECASE, PR_MESSAGE_CLASS, {PT_UNICODE, deconst("IPM.RuleOrganizer")}};
	static constexpr RESTRICTION rst_c[2] = {{RES_EXIST, {deconst(&rst_a)}}, {RES_CONTENT, {deconst(&rst_b)}}};
	static constexpr RESTRICTION_AND_OR rst_d = {std::size(rst_c), deconst(rst_c)};
	static constexpr RESTRICTION rst_e = {RES_AND, {deconst(&rst_d)}};
	uint32_t table_id = 0, rowcount = 0;
	if (!exmdb_client::load_content_table(g_storedir, CP_ACP, inbox,
	    nullptr, TABLE_FLAG_ASSOCIATED, &rst_e, nullptr,
	    &table_id, &rowcount))
		return EIO;
	auto cl_0 = make_scope_exit([&]() { exmdb_client::unload_table(g_storedir, table_id); });
	if (rowcount == 0) {
		printf("0 messages cleared\n");
		return 0;
	}

	static constexpr uint32_t qtags1[] = {PidTagMid};
	static constexpr PROPTAG_ARRAY qtags = {std::size(qtags1), deconst(qtags1)};
	TARRAY_SET rowset{};
	if (!exmdb_client::query_table(g_storedir, nullptr, CP_ACP, table_id,
	    &qtags, 0, rowcount, &rowset))
		return EIO;
	std::vector<uint64_t> ids;
	for (unsigned int i = 0; i < rowset.count; ++i) {
		auto mid = rowset.pparray[i]->get<const uint64_t>(PidTagMid);
		if (mid != nullptr)
			ids.push_back(*mid);
	}

	EID_ARRAY ea_info;
	ea_info.count = ids.size();
	ea_info.pids  = ids.data();
	BOOL partial = false;
	printf("Deleting %u messages...\n", ea_info.count);
	if (!exmdb_client::delete_messages(g_storedir, CP_ACP, nullptr, inbox,
	    &ea_info, 1, &partial))
		return EIO;
	return 0;
}

int main(int argc, char **argv)
{
	using namespace global;

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt5(global::g_options_table, argv, &argc, &argv,
	    HXOPT_RQ_ORDER | HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	auto cl_0 = make_scope_exit([=]() { HX_zvecfree(argv); });
	--argc;
	++argv;
	if (argc == 0)
		return global::help();
	if (g_arg_username != nullptr && g_arg_userdir != nullptr) {
		fprintf(stderr, "Only one of -d and -u must be specified before the subcommand.\n");
		return EXIT_FAILURE;
	} else if (g_arg_username == nullptr && g_arg_userdir == nullptr) {
		fprintf(stderr, "The -d or -u option must be specified before the subcommand.\n");
		return EXIT_FAILURE;
	}

	if (g_arg_username != nullptr) {
		gi_setup_early(g_arg_username);
		if (gi_setup() != EXIT_SUCCESS)
			return EXIT_FAILURE;
	} else if (g_arg_userdir != nullptr) {
		g_storedir = g_arg_userdir;
		if (gi_setup_from_dir() != EXIT_SUCCESS)
			return EXIT_FAILURE;
	}
	auto cl_1 = make_scope_exit(gi_shutdown);

	int ret = EXIT_FAILURE;
	if (strcmp(argv[0], "delmsg") == 0) {
		ret = delmsg::main(argc, argv);
	} else if (strcmp(argv[0], "emptyfld") == 0) {
		ret = emptyfld::main(argc, argv);
	} else if (strcmp(argv[0], "clear-photo") == 0) {
		ret = delstoreprop(argc, argv, PSETID_GROMOX, "photo");
	} else if (strcmp(argv[0], "clear-profile") == 0) {
		ret = delstoreprop(argc, argv, PSETID_GROMOX, "zcore_profsect");
	} else if (strcmp(argv[0], "clear-rwz") == 0) {
		ret = clear_rwz();
	} else if (strcmp(argv[0], "get-photo") == 0) {
		ret = showstoreprop(argc, argv, PSETID_GROMOX, "photo", PT_BINARY);
	} else if (strcmp(argv[0], "set-photo") == 0) {
		ret = setstoreprop(argc, argv, PSETID_GROMOX, "photo", PT_BINARY);
	} else if (strcmp(argv[0], "get-websettings") == 0) {
		ret = showstoreprop(argc, argv, PSETID_GROMOX, "websettings", PT_UNICODE);
	} else if (strcmp(argv[0], "set-websettings") == 0) {
		ret = setstoreprop(argc, argv, PSETID_GROMOX, "websettings", PT_UNICODE);
	} else if (strcmp(argv[0], "get-websettings-persistent") == 0) {
		ret = showstoreprop(argc, argv, PSETID_GROMOX, "websettings_persistent", PT_UNICODE);
	} else if (strcmp(argv[0], "set-websettings-persistent") == 0) {
		ret = setstoreprop(argc, argv, PSETID_GROMOX, "websettings_persistent", PT_UNICODE);
	} else if (strcmp(argv[0], "get-websettings-recipients") == 0) {
		ret = showstoreprop(argc, argv, PSETID_GROMOX, "websettings_recipienthistory", PT_UNICODE);
	} else if (strcmp(argv[0], "set-websettings-recipients") == 0) {
		ret = setstoreprop(argc, argv, PSETID_GROMOX, "websettings_recipienthistory", PT_UNICODE);
	} else if (strcmp(argv[0], "purge-softdelete") == 0) {
		ret = purgesoftdel::main(argc, argv);
	} else if (strcmp(argv[0], "set-locale") == 0) {
		ret = set_locale::main(argc, argv);
	} else {
		ret = simple_rpc::main(argc, argv);
		if (ret == -EINVAL)
			fprintf(stderr, "Unrecognized subcommand \"%s\"\n", argv[0]);
	}
	return !!ret;
}
