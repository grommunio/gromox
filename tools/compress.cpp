// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <vector>
#include <sys/stat.h>
#include <libHX/ctype_helper.h>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/proc.h>
#include <libHX/string.h>
#include <gromox/fileio.h>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>

using namespace std::string_literals;
using namespace gromox;

enum {
	ARG_NONE = 0, ARG_CIDS,
};
static unsigned int g_arg_type, g_dry_run, g_complvl = 6;
static char g_complvl_str[10];
static constexpr HXoption g_options_table[] = {
	{nullptr, 'n', HXTYPE_NONE, &g_dry_run, nullptr, nullptr, 0, "Dry run"},
	{nullptr, 'z', HXTYPE_UINT, &g_complvl, nullptr, nullptr, 0, "Compression level (default: 6)", "LEVEL"},
	{"cid", 0, HXTYPE_VAL, &g_arg_type, nullptr, nullptr, ARG_CIDS, "Process arguments as CID directories/files"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static bool digity(const char *s)
{
	for (; *s != '\0'; ++s)
		if (!HX_isdigit(*s))
			return false;
	return true;
}

static void cid_read_dir(const char *dir, std::vector<std::string> &files)
{
	auto dh = HXdir_open(dir);
	if (dh == nullptr) {
		fprintf(stderr, "%s: %s\n", dir, strerror(errno));
		return;
	}
	auto cl_0 = make_scope_exit([&]() { HXdir_close(dh); });
	const char *de;
	while ((de = HXdir_read(dh)) != nullptr) {
		if (!digity(de))
			continue;
		auto path = dir + "/"s + de;
		/* Do not recurse further */
		struct stat sb;
		if (lstat(path.c_str(), &sb) != 0 || !S_ISREG(sb.st_mode))
			continue;
		files.push_back(std::move(path));
	}
}

static std::vector<std::string> cid_read_args(int argc, const char **argv)
{
	std::vector<std::string> files;
	while (*++argv != nullptr) {
		struct stat sb;
		if (lstat(*argv, &sb) != 0) {
			mlog(LV_ERR, "stat %s: %s", *argv, strerror(errno));
			continue;
		}
		if (S_ISDIR(sb.st_mode)) {
			cid_read_dir(*argv, files);
			continue;
		} else if (!S_ISREG(sb.st_mode)) {
			mlog(LV_ERR, "%s: Not a regular file or directory", *argv);
			continue;
		}
		if (!digity(HX_basename(*argv))) {
			mlog(LV_ERR, "%s: Filename does not look like a content file", *argv);
			continue;
		}
		files.push_back(*argv);
	}
	return files;
}

static int do_file(const std::string &file)
{
	struct stat sb;
	if (stat(file.c_str(), &sb) != 0) {
		mlog(LV_ERR, "stat %s: %s\n", file.c_str(), strerror(errno));
		return EXIT_FAILURE;
	}
	auto v1t_name = file + ".v1t"s;
	auto v1z_name = file + ".v1z"s;
	const char *args[] = {"zstd", g_complvl_str, "-kqo", v1t_name.c_str(), file.c_str(), nullptr};
	auto ret = HXproc_run_sync(args, HXPROC_NULL_STDIN | HXPROC_VERBOSE);
	if (ret != 0) {
		mlog(LV_ERR, "zstd %s exited with error %d\n", file.c_str(), ret);
		unlink(v1t_name.c_str());
		return EXIT_FAILURE;
	}
	if (chown(v1t_name.c_str(), sb.st_uid, sb.st_gid) != 0) {
		mlog(LV_ERR, "chown %s: %s\n", v1t_name.c_str(), strerror(errno));
		unlink(v1t_name.c_str());
		return EXIT_FAILURE;
	}
	if (rename(v1t_name.c_str(), v1z_name.c_str()) != 0) {
		mlog(LV_ERR, "rename %s: %s\n", v1t_name.c_str(), strerror(errno));
		unlink(v1t_name.c_str());
		return EXIT_FAILURE;
	}
	if (unlink(file.c_str()) != 0) {
		mlog(LV_ERR, "unlink %s: %s\n", file.c_str(), strerror(errno));
		unlink(v1z_name.c_str());
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int main(int argc, const char **argv)
{
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;

	std::vector<std::string> filelist;
	if (g_arg_type == ARG_CIDS) {
		filelist = cid_read_args(argc, argv);
	} else {
		mlog(LV_ERR, "A mode of operation must be specified. Available: --cid.");
		return EXIT_FAILURE;
	}
	mlog(LV_NOTICE, "%zu files to compress", filelist.size());
	snprintf(g_complvl_str, std::size(g_complvl_str), "-%u", g_complvl);
	for (auto &&file : filelist) {
		mlog(LV_NOTICE, "* %s", file.c_str());
		if (g_dry_run)
			continue;
		if (do_file(file) != EXIT_SUCCESS)
			return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
