// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <libHX/option.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include "genimport.hpp"

using namespace gromox;
namespace exmdb_client = exmdb_client_remote;

namespace delmsg {

static uint64_t g_folderid;
static unsigned int g_soft;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'f', HXTYPE_UINT64, &g_folderid, nullptr, nullptr, 0, "Folder ID"},
	{"soft", 0, HXTYPE_NONE, &g_soft, nullptr, nullptr, 0, "Soft-delete (experimental)"},
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
	if (!exmdb_client::get_folder_properties(g_storedir, 0, fid,
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
	if (g_folderid == 0)
		return help();
	std::vector<uint64_t> eids;
	while (*++argv != nullptr)
		eids.push_back(rop_util_make_eid_ex(1, strtoull(*argv, nullptr, 0)));
	EID_ARRAY ea;
	ea.count = eids.size();
	ea.pids = eids.data();
	BOOL partial = false;
	eid_t fid = rop_util_make_eid_ex(1, g_folderid);
	auto old_msgc = delcount(fid);
	if (!exmdb_client::delete_messages(g_storedir, g_user_id, CP_UTF8,
	    nullptr, fid, &ea, !g_soft, &partial)) {
		printf("RPC was rejected.\n");
		return EXIT_FAILURE;
	}
	auto diff = delcount(fid) - old_msgc;
	if (partial)
		printf("Partial completion\n");
	printf("%u messages deleted\n", diff);
	return EXIT_SUCCESS;
}

} /* namespace delmsg */

namespace emptyfld {

static unsigned int g_recursive, g_soft;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'R', HXTYPE_NONE, &g_recursive, nullptr, nullptr, 0, "Recurse into subfolders"},
	{"soft", 0, HXTYPE_NONE, &g_soft, nullptr, nullptr, 0, "Soft-delete (experimental)"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static int main(int argc, const char **argv)
{
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	while (*++argv != nullptr) {
		BOOL partial = false;
		auto fid = strtoull(*argv, nullptr, 0);
		auto eid = rop_util_make_eid_ex(1, fid);
		auto old_msgc = delcount(eid);
		auto ok = exmdb_client::empty_folder(g_storedir, CP_UTF8, nullptr,
		          eid, !g_soft, true, false, g_recursive, &partial);
		if (!ok) {
			fprintf(stderr, "empty_folder 0x%llx failed\n",
				static_cast<unsigned long long>(fid));
			return EXIT_FAILURE;
		}
		auto diff = delcount(eid) - old_msgc;
		if (partial)
			printf("Partial completion\n");
		printf("Folder 0x%llx: %u messages deleted\n", fid, diff);
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
	fprintf(stderr, "Command list:\n");
	fprintf(stderr, "\tdelmsg    Issue \"delete_message\" RPCs\n");
	fprintf(stderr, "\temptyfld  Issue \"empty_folder\" RPCs\n");
	fprintf(stderr, "\tunload    Issue the \"unload\" RPC\n");
	fprintf(stderr, "\tvacuum    Issue the \"vacuum\" RPC\n");
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
	if (strcmp(argv[0], "unload") == 0) {
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
	} else {
		ret = simple_rpc::main(argc, argv);
		if (ret == -EINVAL) {
			fprintf(stderr, "Unrecognized subcommand \"%s\"\n", argv[0]);
			ret = EXIT_FAILURE;
		}
	}
	return ret;
}
