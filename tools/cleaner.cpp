// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <dirent.h>
#include <memory>
#include <sqlite3.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <fmt/core.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <gromox/database.h>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/tie.hpp>

using namespace std::string_literals;
using namespace gromox;

namespace {
struct sql_del {
	void operator()(sqlite3 *x) const { sqlite3_close(x); }
};
}

static char *g_maildir;
static unsigned int g_dry_run, g_verbose;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'd', HXTYPE_STRING, &g_maildir, nullptr, nullptr, 0, "Scan this particular directory", "DIR"},
	{nullptr, 'n', HXTYPE_NONE, &g_dry_run, nullptr, nullptr, 0, "Perform a dry run (no deletions)"},
	{nullptr, 'v', HXTYPE_NONE, &g_verbose, nullptr, nullptr, 0, "Print status about every single message"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static bool discover_ids(sqlite3 *db, const std::string &query,
    std::vector<std::string> &used)
{
	auto stm = gx_sql_prep(db, query.c_str());
	if (stm == nullptr)
		return false;
	while (stm.step() == SQLITE_ROW)
		used.push_back(stm.col_text(0));
	return true;
}

static bool discover_cids(const char *dir, std::vector<std::string> &used)
{
	used.clear();
	std::unique_ptr<sqlite3, sql_del> db;
	auto dbpath = dir + "/exmdb/exchange.sqlite3"s;
	auto ret = sqlite3_open_v2(dbpath.c_str(), &unique_tie(db),
	           SQLITE_OPEN_READWRITE, nullptr);
	if (ret != SQLITE_OK) {
		/*
		 * Absence of this file could be seen as used={}. But the
		 * absence would indicate a bigger issue elsewhere... Abort.
		 */
		fprintf(stderr, "Cannot open %s: %s\n", dbpath.c_str(), sqlite3_errstr(ret));
		return false;
	}

	auto query = fmt::format("SELECT propval FROM message_properties "
	             "WHERE proptag IN ({},{},{},{},{},{})",
	             PR_TRANSPORT_MESSAGE_HEADERS,
	             PR_TRANSPORT_MESSAGE_HEADERS_A,
	             PR_BODY, PR_BODY_A, PR_HTML, PR_RTF_COMPRESSED);
	if (!discover_ids(db.get(), query, used))
		return false;
	query = fmt::format("SELECT propval FROM attachment_properties "
	        "WHERE proptag IN ({},{})",
	        PR_ATTACH_DATA_BIN, PR_ATTACH_DATA_OBJ);
	if (!discover_ids(db.get(), query, used))
		return false;
	std::sort(used.begin(), used.end());
	used.erase(std::unique(used.begin(), used.end()), used.end());
	return true;
}

static uint64_t delete_unused_cid_files(const std::string &cid_dir,
    const std::vector<std::string> &used_ids, time_t upper_bound_ts)
{
	std::unique_ptr<DIR, file_deleter> dh(opendir(cid_dir.c_str()));
	if (dh == nullptr) {
		fprintf(stderr, "Cannot open %s: %s\n", cid_dir.c_str(), strerror(errno));
		return UINT64_MAX;
	}
	struct dirent *de;
	auto dfd = dirfd(dh.get());
	uint64_t bytes = 0;
	while ((de = readdir(dh.get())) != nullptr) {
		if (*de->d_name == '.')
			continue;
		if (std::binary_search(used_ids.begin(), used_ids.end(), de->d_name)) {
			if (g_verbose)
				printf("%s: still in use\n", de->d_name);
			continue;
		}
		struct stat sb;
		if (fstatat(dfd, de->d_name, &sb, 0) != 0)
			/* e.g. removal by another racing entity, just don't bother */
			continue;
		if (sb.st_mtime >= upper_bound_ts) {
			if (g_verbose)
				printf("%s: too new to be considered in this run\n", de->d_name);
			continue;
		}
		if (g_verbose) {
			char buf[32];
			HX_unit_size_cu(buf, arsizeof(buf), sb.st_size, 0);
			printf("%s: removing... (%sB)\n", de->d_name, buf);
		}
		if (g_dry_run)
			bytes += sb.st_size;
		else if (unlinkat(dfd, de->d_name, 0) != 0)
			fprintf(stderr, "unlink(%s): %s\n", de->d_name, strerror(errno));
		else
			bytes += sb.st_size;
	}
	char buf[32];
	HX_unit_size(buf, arsizeof(buf), bytes, 0, 0);
	printf("Purged %sB\n", buf);
	return bytes;
}

static bool clean_cid(const char *maildir, time_t upper_bound_ts)
{
	std::vector<std::string> used;
	if (!discover_cids(maildir, used))
		return false;
	return delete_unused_cid_files(maildir + "/cid"s,
	       std::move(used), upper_bound_ts) < UINT64_MAX;
}

int main(int argc, const char **argv)
{
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (g_maildir == nullptr) {
		fprintf(stderr, "You need to specify the mailbox directory with -d\n");
		return EXIT_FAILURE;
	}
	/* Trivial check to help fend off dirs that do not look like a mailbox. */
	auto dbpath = g_maildir + "/exmdb"s;
	if (access(dbpath.c_str(), X_OK) < 0) {
		fprintf(stderr, "%s: %s\n", dbpath.c_str(), strerror(errno));
		return EXIT_FAILURE;
	}
	/*
	 * Querying the database is not atomic, and the server may produce new
	 * attachments/bodies at any time. Therefore, place a limit on what
	 * files we will consider out of all the IDs discovered.
	 *
	 * This is still not completely race-free, as new new attachments are
	 * created on disk before the database is updated. (Either that changes,
	 * or, better yet, the cleaning procedure is added to exmdb_server_delete*.)
	 */
	auto upper_bound_ts = time(nullptr) - 60;
	if (!clean_cid(g_maildir, upper_bound_ts)) {
		fprintf(stderr, "Part of the operation did not complete successfully.\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
