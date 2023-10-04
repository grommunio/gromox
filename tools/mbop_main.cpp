// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "genimport.hpp"

using namespace std::string_literals;
using namespace gromox;
namespace exmdb_client = exmdb_client_remote;

static constexpr std::pair<const char *, uint8_t> fld_special_names[] = {
	{"", PRIVATE_FID_ROOT},
	{"CALENDAR", PRIVATE_FID_CALENDAR},
	{"COMMON_VIEWS", PRIVATE_FID_COMMON_VIEWS},
	{"CONFLICTS", PRIVATE_FID_CONFLICTS},
	{"CONTACTS", PRIVATE_FID_CONTACTS},
	{"DEFERRED_ACTION", PRIVATE_FID_DEFERRED_ACTION},
	{"DELETED", PRIVATE_FID_DELETED_ITEMS},
	{"DRAFT", PRIVATE_FID_DRAFT},
	{"FINDER", PRIVATE_FID_FINDER},
	{"INBOX", PRIVATE_FID_INBOX},
	{"IPM_SUBTREE", PRIVATE_FID_IPMSUBTREE},
	{"JOURNAL", PRIVATE_FID_JOURNAL},
	{"JUNK", PRIVATE_FID_JUNK},
	{"LOCAL_FAILURES", PRIVATE_FID_LOCAL_FAILURES},
	{"NOTES", PRIVATE_FID_NOTES},
	{"OUTBOX", PRIVATE_FID_OUTBOX},
	{"SENT", PRIVATE_FID_SENT_ITEMS},
	{"SERVER_FAILURES", PRIVATE_FID_SERVER_FAILURES},
	{"SHORTCUTS", PRIVATE_FID_SHORTCUTS},
	{"SYNC_ISSUES", PRIVATE_FID_SYNC_ISSUES},
	{"TASKS", PRIVATE_FID_TASKS},
	{"VIEWS", PRIVATE_FID_VIEWS},
};

static eid_t lookup_eid_by_name(const char *dir, const char *name)
{
	auto pathcomp = gx_split(name, '/');
	if (pathcomp.size() == 0)
		return 0;
	auto ptr = std::lower_bound(std::begin(fld_special_names), std::end(fld_special_names),
	           pathcomp[0].c_str(), [](const std::pair<const char *, uint8_t> &pair, const char *x) {
	           	return strcmp(pair.first, x) < 0;
	           });
	if (ptr == std::end(fld_special_names) || strcmp(ptr->first, name) != 0)
		return 0;

	eid_t fid = rop_util_make_eid_ex(1, ptr->second);
	for (size_t i = 1; i < pathcomp.size(); ++i) {
		RESTRICTION_CONTENT rst_4 = {FL_IGNORECASE, PR_DISPLAY_NAME, {PR_DISPLAY_NAME, deconst(pathcomp[i].c_str())}};
		RESTRICTION_EXIST rst_3   = {PR_DISPLAY_NAME};
		RESTRICTION rst_2[2]      = {{RES_EXIST, {&rst_3}}, {RES_CONTENT, {&rst_4}}};
		RESTRICTION_AND_OR rst_1  = {std::size(rst_2), rst_2};
		RESTRICTION rst           = {RES_AND, {&rst_1}};
		uint32_t table_id = 0, rowcount = 0;
		if (!exmdb_client::load_hierarchy_table(dir, fid, nullptr,
		    0, &rst, &table_id, &rowcount)) {
			mlog(LV_ERR, "load_hierarchy_table RPC rejected");
			return 0;
		}
		auto cl_0 = make_scope_exit([&]() { exmdb_client::unload_table(dir, table_id); });

		static constexpr uint32_t qtags[] = {PidTagFolderId};
		static constexpr PROPTAG_ARRAY qtaginfo = {std::size(qtags), deconst(qtags)};
		tarray_set rowset;
		if (!exmdb_client::query_table(dir, nullptr, CP_ACP, table_id,
		    &qtaginfo, 0, rowcount, &rowset)) {
			mlog(LV_ERR, "query_table RPC rejected");
			return 0;
		}
		if (rowset.count == 0) {
			mlog(LV_ERR, "Could not locate \"%s\".", pathcomp[i].c_str());
			return 0;
		} else if (rowset.count > 1) {
			mlog(LV_ERR, "\"%s\" is ambiguous.", pathcomp[i].c_str());
			return 0;
		}
		auto newfid = rowset.pparray[0]->get<const eid_t>(PidTagFolderId);
		if (newfid == nullptr)
			return 0;
		fid = *newfid;
	}
	return fid;
}

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

static uint32_t delcount(eid_t fid)
{
	static constexpr uint32_t tag_msgc = PR_DELETED_COUNT_TOTAL;
	static constexpr PROPTAG_ARRAY tags_msgc = {1, deconst(&tag_msgc)};
	TPROPVAL_ARRAY props;
	if (!exmdb_client::get_folder_properties(g_storedir, CP_ACP, fid,
	    &tags_msgc, &props))
		return 0;
	auto c = props.get<const uint32_t>(tag_msgc);
	return c != nullptr ? *c : 0;
}

namespace delmsg {

static int main(int argc, const char **argv)
{
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (g_folderstr != nullptr) {
		char *end = nullptr;
		uint64_t fid = strtoul(g_folderstr, &end, 0);
		if (end == g_folderstr || *end != '\0')
			g_folderid = lookup_eid_by_name(g_storedir, g_folderstr);
		else
			g_folderid = rop_util_make_eid_ex(1, fid);
	}
	if (rop_util_get_gc_value(g_folderid) == 0)
		return help();
	std::vector<uint64_t> eids;
	while (*++argv != nullptr) {
		uint64_t id = strtoull(*argv, nullptr, 0);
		eid_t eid = id == 0 ? lookup_eid_by_name(g_storedir, *argv) : rop_util_make_eid_ex(1, id);
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
	auto old_msgc = delcount(g_folderid);
	if (!exmdb_client::delete_messages(g_storedir, g_user_id, CP_UTF8,
	    nullptr, g_folderid, &ea, !g_soft, &partial)) {
		printf("RPC was rejected.\n");
		return EXIT_FAILURE;
	}
	auto diff = delcount(g_folderid) - old_msgc;
	if (partial)
		printf("Partial completion\n");
	printf("%u messages deleted\n", diff);
	return EXIT_SUCCESS;
}

} /* namespace delmsg */

namespace emptyfld {

static unsigned int g_del_flags = DEL_MESSAGES | DELETE_HARD_DELETE;

static void opt_m(const struct HXoptcb *cb) { g_del_flags &= ~DEL_MESSAGES; }
static void opt_r(const struct HXoptcb *cb) { g_del_flags |= DEL_FOLDERS; }
static void opt_a(const struct HXoptcb *cb) { g_del_flags |= DEL_ASSOCIATED; }
static void opt_s(const struct HXoptcb *cb) { g_del_flags &= ~DELETE_HARD_DELETE; }

static constexpr HXoption g_options_table[] = {
	{nullptr, 'M', HXTYPE_NONE, {}, {}, opt_m, 0, "Exclude normal messages from deletion"},
	{nullptr, 'R', HXTYPE_NONE, {}, {}, opt_r, 0, "Recurse into subfolders"},
	{nullptr, 'a', HXTYPE_NONE, {}, {}, opt_a, 0, "Include associated messages in deletion"},
	{"soft",    0, HXTYPE_NONE, {}, {}, opt_s, 0, "Soft-delete (experimental)"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static int main(int argc, const char **argv)
{
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	while (*++argv != nullptr) {
		BOOL partial = false;
		uint64_t id = strtoull(*argv, nullptr, 0);
		eid_t eid = id == 0 ? lookup_eid_by_name(g_storedir, *argv) : rop_util_make_eid_ex(1, id);
		if (eid == 0) {
			fprintf(stderr, "Not recognized/found: \"%s\"\n", *argv);
			return EXIT_FAILURE;
		}
		auto old_msgc = delcount(eid);
		auto ok = exmdb_client::empty_folder(g_storedir, CP_UTF8, nullptr,
		          eid, g_del_flags, &partial);
		if (!ok) {
			fprintf(stderr, "empty_folder %s failed\n", *argv);
			return EXIT_FAILURE;
		}
		auto diff = delcount(eid) - old_msgc;
		if (partial)
			printf("Partial completion\n");
		printf("Folder %s: %u messages deleted\n", *argv, diff);
	}
	return EXIT_SUCCESS;
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

static int main(int argc, const char **argv)
{
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	auto age = rop_util_unix_to_nttime(time(nullptr) - HX_strtoull_sec(znul(g_age_str), nullptr));
	while (*++argv != nullptr) {
		uint64_t id = strtoull(*argv, nullptr, 0);
		eid_t eid = id == 0 ? lookup_eid_by_name(g_storedir, *argv) : rop_util_make_eid_ex(1, id);
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
	fprintf(stderr, "Usage: gromox-mbop [global-options] command [command-args...]\n");
	fprintf(stderr, "Global options:\n");
	fprintf(stderr, "\t-u emailaddr/-d directory    Name of/path to mailbox\n");
	fprintf(stderr, "Commands:\n\tclear-photo clear-profile delmsg emptyfld purge-datafiles unload vacuum\n");
	return EXIT_FAILURE;
}

} /* namespace global */

namespace simple_rpc {

static constexpr HXoption g_options_table[] = {
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static int main(int argc, const char **argv)
{
	bool ok = false;
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (strcmp(argv[0], "purge-datafiles") == 0) {
		ok = exmdb_client::purge_datafiles(g_storedir);
	} else if (strcmp(argv[0], "unload") == 0) {
		ok = exmdb_client::unload_store(g_storedir);
	} else if (strcmp(argv[0], "vacuum") == 0) {
		ok = exmdb_client::vacuum(g_storedir);
	} else {
		return -EINVAL;
	}
	if (!ok) {
		fprintf(stderr, "%s: the operation failed\n", argv[0]);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

}

static errno_t delstoreprop(const GUID &guid, const char *name)
{
	const PROPERTY_NAME xn = {MNID_STRING, guid, 0, deconst(name)};
	const PROPNAME_ARRAY name_req = {1, deconst(&xn)};
	PROPID_ARRAY name_rsp{};
	if (!exmdb_client::get_named_propids(g_storedir, false, &name_req, &name_rsp))
		return EINVAL;
	if (name_rsp.count != name_req.count)
		return EINVAL;
	if (name_rsp.ppropid[0] == 0)
		return 0;
	uint32_t proptag = PROP_TAG(PT_BINARY, name_rsp.ppropid[0]);
	/* In the future, some names may require us to use a different PT */
	const PROPTAG_ARRAY tags = {1, &proptag};
	if (!exmdb_client::remove_store_properties(g_storedir, &tags))
		return EINVAL;
	if (strcmp(name, "zcore_profsect") == 0)
		unlink((g_storedir + "/config/zarafa.dat"s).c_str());
	else if (strcmp(name, "photo") == 0)
		unlink((g_storedir + "/config/portrait.jpg"s).c_str());
	return 0;
}

int main(int argc, const char **argv)
{
	using namespace global;

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(global::g_options_table, &argc, &argv,
	    HXOPT_RQ_ORDER | HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	--argc;
	++argv;
	if (argc == 0)
		return global::help();
	if (g_arg_username != nullptr && g_arg_userdir != nullptr) {
		fprintf(stderr, "Can only specify one of -d or -u\n");
		return EXIT_FAILURE;
	} else if (g_arg_username == nullptr && g_arg_userdir == nullptr) {
		fprintf(stderr, "Must specify either -d or -u\n");
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

	int ret = EXIT_FAILURE;
	if (strcmp(argv[0], "delmsg") == 0) {
		ret = delmsg::main(argc, argv);
	} else if (strcmp(argv[0], "emptyfld") == 0) {
		ret = emptyfld::main(argc, argv);
	} else if (strcmp(argv[0], "clear-photo") == 0) {
		ret = delstoreprop(PSETID_GROMOX, "photo");
	} else if (strcmp(argv[0], "clear-profile") == 0) {
		ret = delstoreprop(PSETID_GROMOX, "zcore_profsect");
	} else if (strcmp(argv[0], "purge-softdelete") == 0) {
		ret = purgesoftdel::main(argc, argv);
	} else {
		ret = simple_rpc::main(argc, argv);
		if (ret == -EINVAL) {
			fprintf(stderr, "Unrecognized subcommand \"%s\"\n", argv[0]);
			ret = EXIT_FAILURE;
		}
	}
	gi_shutdown();
	return ret;
}
