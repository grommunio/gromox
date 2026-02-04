// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022–2026 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <libHX/socket.h>
#include <libHX/string.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/fileio.h>
#include <gromox/freebusy.hpp>
#include <gromox/mapidefs.h>
#include <gromox/process.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>
#include "genimport.hpp"
#include "mbop.hpp"

using namespace std::string_literals;
using namespace gromox;

const struct HXoption empty_options_table[] = {
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

bool g_exit_after_optparse;

void mbop_help_cb(const struct HXoptcb *cbi)
{
	HX_getopt_help(cbi, stdout);
	g_exit_after_optparse = true;
}

void mbop_usage_cb(const struct HXoptcb *cbi)
{
	HX_getopt_usage(cbi, stdout);
	g_exit_after_optparse = true;
}

void delcount(eid_t fid, uint32_t *delc, uint32_t *fldc)
{
	static constexpr proptag_t tags[] = {PR_DELETED_COUNT_TOTAL, PR_FOLDER_CHILD_COUNT};
	TPROPVAL_ARRAY props;
	*delc = *fldc = 0;
	if (!exmdb_client->get_folder_properties(g_storedir, CP_ACP, fid,
	    tags, &props)) {
		mbop_fprintf(stderr, "delcount: get_folder_properties failed\n");
		return;
	}
	auto c = props.get<const uint32_t>(tags[0]);
	*delc = c != nullptr ? *c : 0;
	c = props.get<const uint32_t>(tags[1]);
	*fldc = c != nullptr ? *c : 0;
}

namespace global {

const char *g_arg_username, *g_arg_userdir;
unsigned int g_continuous_mode, g_verbose_mode, g_command_num;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_NONE, &g_continuous_mode, {}, {}, {}, "Do not stop on errors"},
	{nullptr, 'v', HXTYPE_NONE, &g_verbose_mode, {}, {}, {}, "Be a little more talkative"},
	{{}, 'd', HXTYPE_STRING, {}, {}, {}, 0, "Directory of the mailbox", "DIR"},
	{{}, 'u', HXTYPE_STRING, {}, {}, {}, 0, "Username of store to import to", "EMAILADDR"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

void command_overview()
{
	fprintf(stderr, "Commands:\n\tcgkreset clear-photo clear-profile "
		"clear-rwz delmsg echo-maildir echo-username emptyfld "
		"freeze get-freebusy get-photo get-websettings "
		"get-websettings-persistent get-websettings-recipients ping "
		"purge-datafiles purge-softdelete recalc-sizes set-locale "
		"set-photo set-websettings set-websettings-persistent "
		"set-websettings-recipients sync-midb thaw unload vacuum\n");
	fprintf(stderr, "Command chaining: ( command1 c1args... ) ( command2 c2args... )...\n");
}

static int help()
{
	fprintf(stderr, "Usage: gromox-mbop [global-options] command [command-options] [command-args...]\n");
	fprintf(stderr, "Global options:\n");
	fprintf(stderr, "\t-?                           Global help (this text)\n");
	fprintf(stderr, "\t-c                           Continus operation mode\n");
	fprintf(stderr, "\t-u emailaddr/-d directory    Name of/path to mailbox\n");
	command_overview();
	fprintf(stderr, "Command options:\n");
	fprintf(stderr, "\t-?                           Call up option help for subcommand\n");
	return EXIT_PARAM;
}

} /* namespace global */

namespace simple_rpc {

static constexpr HXoption g_options_table[] = {
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

static inline uint64_t inul(const uint64_t *v)
{
	return v != nullptr ? *v : 0;
}

static bool recalc_sizes(const char *dir)
{
	static constexpr proptag_t tags[] = {
		PR_MESSAGE_SIZE_EXTENDED, PR_NORMAL_MESSAGE_SIZE_EXTENDED,
		PR_ASSOC_MESSAGE_SIZE_EXTENDED
	};
	TPROPVAL_ARRAY vals;
	auto ok = exmdb_client->get_store_properties(dir, CP_ACP, tags, &vals);
	if (!ok)
		return false;
	printf("Old: %llu bytes (%llu normal, %llu FAI)\n",
	       LLU{inul(vals.get<uint64_t>(tags[0]))},
	       LLU{inul(vals.get<uint64_t>(tags[1]))},
	       LLU{inul(vals.get<uint64_t>(tags[2]))});
	ok = exmdb_client->recalc_store_size(g_storedir, 0);
	if (!ok)
		return false;
	ok = exmdb_client->get_store_properties(g_storedir, CP_ACP, tags, &vals);
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
	if (HX_getopt6(g_options_table, argc, argv, nullptr,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;
	if (strcmp(argv[0], "purge-datafiles") == 0)
		ok = exmdb_client->purge_datafiles(g_storedir);
	else if (strcmp(argv[0], "echo-username") == 0) {
		printf("%s\n", g_storedir);
		ok = true;
	} else if (strcmp(argv[0], "echo-username") == 0) {
		printf("%s\n", g_dstuser.c_str());
		ok = true;
	} else if (strcmp(argv[0], "ping") == 0)
		ok = exmdb_client->ping_store(g_storedir);
	else if (strcmp(argv[0], "unload") == 0)
		ok = exmdb_client->unload_store(g_storedir);
	else if (strcmp(argv[0], "thaw") == 0)
		ok = exmdb_client->set_maintenance(g_storedir, static_cast<uint32_t>(db_maint_mode::usable));
	else if (strcmp(argv[0], "vacuum") == 0)
		ok = exmdb_client->vacuum(g_storedir);
	else if (strcmp(argv[0], "recalc-sizes") == 0)
		ok = recalc_sizes(g_storedir);
	else {
		mbop_fprintf(stderr, "Unrecognized subcommand \"%s\"\n", argv[0]);
		return EXIT_PARAM;
	}
	if (!ok) {
		mbop_fprintf(stderr, "%s: the operation failed\n", argv[0]);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

} /* namespace simple_rpc */

namespace set_maint {

static unsigned int g_fast;
static constexpr HXoption g_options_table[] = {
	{"no-wait", 0, HXTYPE_NONE, &g_fast, {}, {}, 0, "Do not wait for reference count to reach zero"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

static int freeze_main(int argc, char **argv)
{
	if (HX_getopt6(g_options_table, argc, argv, nullptr,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;
	/*
	 * db_maint_mode::hold is not offered presently, since exmdb is prone
	 * to get into out-of-memory situations when used.
	 */
	enum db_maint_mode mode = g_fast ? db_maint_mode::reject :
	                          db_maint_mode::reject_waitforexcl;
	auto ok = exmdb_client->set_maintenance(g_storedir, static_cast<uint32_t>(mode));
	if (!ok) {
		mbop_fprintf(stderr, "%s: the operation failed\n", argv[0]);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

}

namespace sync_midb {

static const char *g_folder_spec;
static constexpr HXoption g_options_table[] = {
	{{}, 'f', HXTYPE_STRP, &g_folder_spec, {}, {}, {}, "Forcibly rescan this folder", "SPEC"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

static int send_cmd(const char *host, uint16_t port, const std::string &cmd)
{
	int fd = HX_inet_connect(host, port, 0);
	if (fd < 0) {
		fprintf(stderr, "connect [%s]:%hu: %s", host, port, strerror(errno));
		return -1;
	}
	std::unique_ptr<FILE, file_deleter> fp(fdopen(fd, "r+"));
	if (fp == nullptr) {
		perror("fdopen");
		return -1;
	}
	setvbuf(fp.get(), nullptr, _IOLBF, 0);
	hxmc_t *line = nullptr;
	auto cl_0 = HX::make_scope_exit([&]() { HXmc_free(line); });
	if (HX_getl(&line, fp.get()) == nullptr)
		return -1;
	if (strcmp(line, "OK\r\n") != 0) {
		fprintf(stderr, "No MIDB intro line received\n");
		return -1;
	}
	fprintf(fp.get(), "%s", cmd.c_str());
	if (HX_getl(&line, fp.get()) == nullptr) {
		fprintf(stderr, "MIDB connection aborted?!\n");
		return -1;
	}
	if (strncasecmp(line, "true", 4) == 0 && HX_isspace(line[4]))
		return 0;
	mbop_fprintf(stderr, "MIDB command unsuccessful\n");
	return 1;
}

int main(int argc, char **argv)
{
	HXopt6_auto_result argp;
	const char *host = "localhost";
	uint16_t port = 5555;

	if (HX_getopt6(g_options_table, argc, argv, nullptr,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;

	int ret;
	if (g_folder_spec == nullptr) {
		ret = send_cmd(host, port, "M-PING " + g_storedir_s + "\r\n");
	} else if (strcasecmp(g_folder_spec, "all") == 0) {
		ret = send_cmd(host, port, "X-RSYM " + g_storedir_s + "\r\n");
	} else {
		auto eid = gi_lookup_eid_any_way(g_storedir, g_folder_spec);
		if (eid == 0) {
			mbop_fprintf(stderr, "Not recognized/found: \"%s\"\n", g_folder_spec);
			return EXIT_FAILURE;
		}
		ret = send_cmd(host, port, "X-RSYF " + g_storedir_s + " " + std::to_string(eid.gcv()) + "\r\n");
	}
	return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

}

static errno_t resolvename(const GUID &guid, const char *name, bool create,
    uint16_t *out)
{
	const PROPERTY_NAME xn = {MNID_STRING, guid, 0, deconst(name)};
	const PROPNAME_ARRAY name_req = {1, deconst(&xn)};
	PROPID_ARRAY name_rsp{};
	if (!exmdb_client->get_named_propids(g_storedir, create, &name_req, &name_rsp))
		return EINVAL;
	if (name_rsp.size() != name_req.size())
		return EINVAL;
	if (name_rsp[0] == 0)
		return ENOENT;
	*out = name_rsp[0];
	return 0;
}

static int delstoreprop(int argc, char **argv, const GUID &guid,
    const char *name, uint16_t type)
{
	if (HX_getopt6(empty_options_table, argc, argv, nullptr,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;

	propid_t propid = 0;
	auto err = resolvename(guid, name, false, &propid);
	if (err == ENOENT)
		return EXIT_SUCCESS;
	else if (err != 0)
		return EXIT_FAILURE;
	auto proptag = PROP_TAG(type, propid);
	const PROPTAG_ARRAY tags = {1, &proptag};
	if (!exmdb_client->remove_store_properties(g_storedir, tags))
		return EXIT_FAILURE;
	if (strcmp(name, "zcore_profsect") == 0)
		unlink((g_storedir + "/config/zarafa.dat"s).c_str());
	else if (strcmp(name, "photo") == 0)
		unlink((g_storedir + "/config/portrait.jpg"s).c_str());
	return EXIT_SUCCESS;
}

static errno_t showstoreprop(proptag_t proptag)
{
	TPROPVAL_ARRAY vals{};
	if (!exmdb_client->get_store_properties(g_storedir, CP_ACP,
	    {&proptag, 1}, &vals))
		return EINVAL;
	switch (PROP_TYPE(proptag)) {
	case PT_BINARY: {
		auto bv = vals.get<const BINARY>(proptag);
		if (bv == nullptr) {
			if (isatty(STDERR_FILENO))
				mbop_fprintf(stderr, "Property is unset\n");
			return 0;
		}
		if (isatty(STDOUT_FILENO) && isatty(STDERR_FILENO))
			mbop_fprintf(stderr, "[%u bytes of binary data]\n", bv->cb);
		if (!isatty(STDOUT_FILENO)) {
			auto ret = HXio_fullwrite(STDOUT_FILENO, bv->pc, bv->cb);
			if (ret < 0 || static_cast<size_t>(ret) != bv->cb)
				return EXIT_FAILURE;
		}
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

static int showstoreprop(int argc, char **argv, const GUID guid,
    const char *name, proptype_t proptype)
{
	if (HX_getopt6(empty_options_table, argc, argv, nullptr,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;

	propid_t propid = 0;
	auto err = resolvename(guid, name, false, &propid);
	if (err == ENOENT)
		return EXIT_SUCCESS;
	else if (err != 0)
		return EXIT_FAILURE;
	return showstoreprop(PROP_TAG(proptype, propid));
}

static errno_t setstoreprop(proptag_t proptag)
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
	if (!exmdb_client->set_store_properties(g_storedir, CP_ACP, &tprop_arr, &prob)) {
		mlog(LV_ERR, "set_store_prop RPC unsuccessful");
		return EIO;
	} else if (prob.count > 0) {
		mlog(LV_ERR, "set_store_prop action unsuccessful / property rejected");
		return EIO;
	}
	return 0;
}

static int setstoreprop(int argc, char **argv, const GUID guid,
    const char *name, proptype_t proptype)
{
	if (HX_getopt6(empty_options_table, argc, argv, nullptr,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;

	propid_t propid = 0;
	auto err = resolvename(guid, name, true, &propid);
	if (err == ENOENT) {
		mbop_fprintf(stderr, "namedprop %s not found\n", name);
		return EXIT_FAILURE;
	} else if (err != 0) {
		mbop_fprintf(stderr, "%s\n", strerror(-err));
		return EXIT_FAILURE;
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
	if (!exmdb_client->load_content_table(g_storedir, CP_ACP, inbox,
	    nullptr, TABLE_FLAG_ASSOCIATED, &rst_e, nullptr,
	    &table_id, &rowcount))
		return EIO;
	auto cl_0 = HX::make_scope_exit([&]() { exmdb_client->unload_table(g_storedir, table_id); });
	if (rowcount == 0) {
		printf("0 messages cleared\n");
		return 0;
	}

	static constexpr proptag_t qtags1[] = {PidTagMid};
	TARRAY_SET rowset{};
	if (!exmdb_client->query_table(g_storedir, nullptr, CP_ACP, table_id,
	    qtags1, 0, rowcount, &rowset))
		return EIO;
	std::vector<eid_t> ids;
	for (unsigned int i = 0; i < rowset.count; ++i) {
		auto mid = rowset.pparray[i]->get<const eid_t>(PidTagMid);
		if (mid != nullptr)
			ids.push_back(*mid);
	}

	EID_ARRAY ea_info;
	ea_info.count = ids.size();
	ea_info.pids  = ids.data();
	BOOL partial = false;
	printf("Deleting %u message(s)...\n", ea_info.count);
	if (!exmdb_client->delete_messages(g_storedir, CP_ACP, nullptr, inbox,
	    &ea_info, 1, &partial))
		return EIO;
	return 0;
}

static int single_user_wrap(int argc, char **argv)
{
	using namespace global;
	if (g_arg_username != nullptr && g_arg_userdir != nullptr) {
		fprintf(stderr, "Only one of -d and -u must be specified before the subcommand.\n");
		return EXIT_FAILURE;
	} else if (g_arg_username == nullptr && g_arg_userdir == nullptr) {
		fprintf(stderr, "The -d or -u option must be specified before the subcommand.\n");
		return EXIT_FAILURE;
	}

	if (g_arg_username != nullptr) {
		if (gi_setup_from_user(g_arg_username) != EXIT_SUCCESS)
			return EXIT_FAILURE;
	} else if (g_arg_userdir != nullptr) {
		if (gi_setup_from_dir(g_arg_userdir) != EXIT_SUCCESS)
			return EXIT_FAILURE;
	}

	auto ret = gi_startup_client();
	if (ret == EXIT_SUCCESS)
		ret = cmd_parser(argc, argv);
	gi_shutdown();
	return ret;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, nullptr, _IOLBF, 0);
	HXopt6_auto_result result;
	if (HX_getopt6(global::g_options_table, argc, argv, &result,
	    HXOPT_USAGEONERR | HXOPT_RQ_ORDER | HXOPT_ITER_OA) != HXOPT_ERR_SUCCESS ||
	    g_exit_after_optparse)
		return EXIT_PARAM;
	for (int i = 0; i < result.nopts; ++i) {
		if (result.desc[i]->sh == 'd')
			global::g_arg_userdir = result.oarg[i];
		else if (result.desc[i]->sh == 'u')
			global::g_arg_username = result.oarg[i];
	}
	argc = result.nargs;
	argv = result.uarg;
	if (argc == 0)
		return global::help();
	service_init({nullptr, {}, 2});
	auto cl_1 = HX::make_scope_exit(service_stop);
	if (service_run() != 0) {
		fprintf(stderr, "service_run: failed\n");
		return EXIT_FAILURE;
	}
	if (strncmp(argv[0], "foreach.", 8) == 0 ||
	    strncmp(argv[0], "for-all-", 8) == 0)
		return foreach_wrap::main(argc, argv);
	else
		return single_user_wrap(argc, argv);
}

namespace global {

static int parens_parser(int argc, char **argv)
{
	unsigned int qcount = 0;
	int start = 0;

	for (int scanpos = 0; scanpos < argc; ++scanpos) {
		if (strcmp(argv[scanpos], "(") == 0) {
			++qcount;
			if (start == 0)
				start = scanpos + 1;
		} else if (strcmp(argv[scanpos], ")") == 0) {
			if (qcount == 0) {
				fprintf(stderr, "Unbalanced parenthesis\n");
				return EXIT_FAILURE;
			}
			--qcount;
			if (qcount == 0) {
				std::vector<char *> args(&argv[start], &argv[scanpos]);
				args.push_back(nullptr);
				auto ret = cmd_parser(std::min(static_cast<size_t>(INT_MAX), args.size() - 1), &args[0]);
				if (ret != EXIT_SUCCESS && !g_continuous_mode)
					return ret;
				start = 0;
			}
		} else if (qcount == 0) {
			fprintf(stderr, "Expected parenthesis; got \"%s\"\n", argv[scanpos]);
			return EXIT_FAILURE;
		}
	}
	if (qcount != 0) {
		fprintf(stderr, "Unbalanced parenthesis\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int cmd_parser(int argc, char **argv)
{
	if (argc == 0)
		return EXIT_FAILURE;
	if (strcmp(argv[0], "(") == 0)
		return parens_parser(argc, argv);
	++g_command_num;
	if (strcmp(argv[0], "delmsg") == 0)
		return delmsg::main(argc, argv);
	else if (strcmp(argv[0], "emptyfld") == 0)
		return emptyfld::main(argc, argv);
	else if (strcmp(argv[0], "clear-photo") == 0)
		return delstoreprop(argc, argv, PSETID_Gromox, "photo", PT_BINARY);
	else if (strcmp(argv[0], "clear-rwz") == 0)
		return clear_rwz();
	else if (strcmp(argv[0], "get-photo") == 0)
		return showstoreprop(argc, argv, PSETID_Gromox, "photo", PT_BINARY);
	else if (strcmp(argv[0], "set-photo") == 0)
		return setstoreprop(argc, argv, PSETID_Gromox, "photo", PT_BINARY);
	else if (strcmp(argv[0], "get-websettings") == 0)
		return showstoreprop(argc, argv, PSETID_Gromox, "websettings", PT_UNICODE);
	else if (strcmp(argv[0], "set-websettings") == 0)
		return setstoreprop(argc, argv, PSETID_Gromox, "websettings", PT_UNICODE);
	else if (strcmp(argv[0], "get-websettings-persistent") == 0)
		return showstoreprop(argc, argv, PSETID_Gromox, "websettings_persistent", PT_UNICODE);
	else if (strcmp(argv[0], "set-websettings-persistent") == 0)
		return setstoreprop(argc, argv, PSETID_Gromox, "websettings_persistent", PT_UNICODE);
	else if (strcmp(argv[0], "get-websettings-recipients") == 0)
		return showstoreprop(argc, argv, PSETID_Gromox, "websettings_recipienthistory", PT_UNICODE);
	else if (strcmp(argv[0], "set-websettings-recipients") == 0)
		return setstoreprop(argc, argv, PSETID_Gromox, "websettings_recipienthistory", PT_UNICODE);
	else if (strcmp(argv[0], "purge-softdelete") == 0)
		return purgesoftdel::main(argc, argv);
	else if (strcmp(argv[0], "set-locale") == 0)
		return set_locale::main(argc, argv);
	else if (strcmp(argv[0], "get-freebusy") == 0 || strcmp(argv[0], "gfb") == 0)
		return getfreebusy::main(argc, argv);
	else if (strcmp(argv[0], "sync-midb") == 0)
		return sync_midb::main(argc, argv);

	if (strcmp(argv[0], "clear-profile") == 0) {
		auto ret = delstoreprop(argc, argv, PSETID_Gromox, "zcore_profsect", PT_BINARY);
		if (ret == 0)
			ret = delstoreprop(argc, argv, PSETID_Gromox, "websettings", PT_UNICODE);
		if (ret == 0)
			ret = delstoreprop(argc, argv, PSETID_Gromox, "websettings_persistent", PT_UNICODE);
		if (ret == 0)
			ret = delstoreprop(argc, argv, PSETID_Gromox, "websettings_recipienthistory", PT_UNICODE);
		return ret;
	} else if (strcmp(argv[0], "echo-maildir") == 0) {
		printf("%s\n", g_storedir);
		return EXIT_SUCCESS;
	} else if (strcmp(argv[0], "echo-username") == 0) {
		printf("%s\n", g_dstuser.c_str());
		return EXIT_SUCCESS;
	} else if (strcmp(argv[0], "cgkreset") == 0) {
		return cgkreset::main(argc, argv);
	} else if (strcmp(argv[0], "freeze") == 0) {
		return set_maint::freeze_main(argc, argv);
	} else if (strcmp(argv[0], "zaddrxlat") == 0) {
		return zaddrxlat::main(argc, argv);
	}
	return simple_rpc::main(argc, argv);
}

}
