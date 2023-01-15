// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sqlite3.h>
#include <string>
#include <unistd.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <gromox/database.h>
#include <gromox/defs.h>
#include <gromox/scope.hpp>
#include <gromox/tie.hpp>

using namespace std::string_literals;
using namespace gromox;
namespace {
struct sqlite_del {
	inline void operator()(sqlite3 *x) const { sqlite3_close(x); }
};
}

static constexpr HXoption g_options_table[] = {
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static errno_t copy_perms(const char *old_file, const char *new_file)
{
	struct stat sb;
	if (stat(old_file, &sb) != 0 ||
	    chmod(new_file, sb.st_mode) != 0 ||
	    chown(new_file, sb.st_uid, sb.st_gid) != 0)
		return errno;
	return 0;
}

static errno_t copy_skel(sqlite3 *db)
{
	auto stm = gx_sql_prep(db, "SELECT `type`, `tbl_name`, `sql` "
	           "FROM `source`.`sqlite_schema` WHERE `sql` IS NOT NULL");
	if (stm == nullptr)
		return EIO;
	while (stm.step() == SQLITE_ROW) {
		fprintf(stderr, "%s %s\n", stm.col_text(0), stm.col_text(1));
		if (strncmp(stm.col_text(1), "sqlite_", 7) == 0)
			continue;
		auto ret = gx_sql_exec(db, stm.col_text(2));
		if (ret != SQLITE_OK)
			return EIO;
	}
	return 0;
}

static errno_t copy_contents(sqlite3 *db)
{
	auto stm = gx_sql_prep(db, "SELECT DISTINCT `tbl_name` FROM `sqlite_schema`");
	if (stm == nullptr)
		return EIO;
	while (stm.step() == SQLITE_ROW) {
		fprintf(stderr, "contents of %s...\n", stm.col_text(0));
		std::unique_ptr<char[], stdlib_delete> qbuf;
		auto qname = HX_strquote(stm.col_text(0), HXQUOTE_SQLBQUOTE,
		             &unique_tie(qbuf));
		if (qname == nullptr)
			return errno;
		auto qstr = "INSERT INTO `"s + qname + "` SELECT * "
		            "FROM `source`.`" + qname + "`";
		auto ret = gx_sql_exec(db, qstr.c_str());
		if (ret != SQLITE_OK)
			return EIO;
	}
	return 0;
}

static int do_file(const char *old_file)
{
	auto new_file = old_file + ".rebuild."s + std::to_string(getpid());
	std::unique_ptr<sqlite3, sqlite_del> db;
	auto ret = sqlite3_open_v2(new_file.c_str(), &unique_tie(db),
	           SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "sqlite3_open %s: %s\n", new_file.c_str(),
		        sqlite3_errstr(ret));
		return EXIT_FAILURE;
	}
	auto auto_unlink = make_scope_exit([&]() { unlink(new_file.c_str()); });
	copy_perms(old_file, new_file.c_str());
	std::unique_ptr<char[], stdlib_delete> fq_buf;
	auto old_fq = HX_strquote(old_file, HXQUOTE_SQLSQUOTE, &unique_tie(fq_buf));
	if (old_fq == nullptr) {
		perror("HX_strquote");
		return EXIT_FAILURE;
	}
	auto qstr = "ATTACH DATABASE '"s + old_fq + "' AS `source`";
	ret = gx_sql_exec(db.get(), qstr.c_str());
	if (ret != SQLITE_OK) {
		fprintf(stderr, "attach %s: %s\n", old_file, sqlite3_errstr(ret));
		return EXIT_FAILURE;
	}
	fprintf(stderr, "=== Processing %s...\n", old_file);
	if (copy_skel(db.get()) != 0 || copy_contents(db.get()) != 0)
		return EXIT_FAILURE;
	ret = rename(new_file.c_str(), old_file);
	if (ret != 0) {
		fprintf(stderr, "W-1395: rename %s -> %s: %s\n",
		        new_file.c_str(), old_file, strerror(errno));
		return EXIT_FAILURE;
	}
	auto_unlink.release();
	return 0;
}

int main(int argc, const char **argv)
{
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (argc < 2) {
		fprintf(stderr, "Usage: %s xyz.sqlite3[...]\n", argv[0]);
		return EXIT_FAILURE;
	}
	auto ret = sqlite3_initialize();
	if (ret != SQLITE_OK) {
		fprintf(stderr, "sqlite3_init: %s\n", sqlite3_errstr(ret));
		return EXIT_FAILURE;
	}
	auto cl_0 = make_scope_exit(sqlite3_shutdown);
	int main_ret = EXIT_SUCCESS;
	while (--argc > 0) {
		ret = do_file(*++argv);
		if (ret != EXIT_SUCCESS)
			main_ret = ret;
		if (argc > 1)
			fprintf(stderr, "\n");
	}
	return main_ret;
}
