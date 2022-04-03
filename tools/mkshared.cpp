// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021–2022 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sqlite3.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/io.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <gromox/database.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/list_file.hpp>
#include <gromox/mapidefs.h>
#include <gromox/pcl.hpp>
#include <gromox/proptags.hpp>
#include <gromox/rop_util.hpp>
#include "mkshared.hpp"

using namespace gromox;

void adjust_rights(int fd)
{
	uid_t uid = -1;
	gid_t gid = -1;
	unsigned int mode = S_IRUSR | S_IWUSR;
	struct stat sb;

	if (fstat(fd, &sb) != 0) {
		perror("fstat");
		return;
	}
	if (S_ISDIR(sb.st_mode))
		mode |= S_IXUSR;
	auto sp = getpwnam("gromox");
	if (sp == nullptr)
		fprintf(stderr, "No \"gromox\" user in system. Not changing UID of mailbox.\n");
	else
		uid = sp->pw_uid;
	auto gr = getgrnam("gromox");
	if (gr == nullptr) {
		fprintf(stderr, "No \"gromox\" group in system. Not changing GID of mailbox.\n");
	} else {
		gid = gr->gr_gid;
		mode |= S_IRGRP | S_IWGRP;
		if (S_ISDIR(sb.st_mode))
			mode |= S_IXGRP;
	}
	if (fchown(fd, uid, gid) < 0)
		perror("fchown");
	if (fchmod(fd, mode) < 0)
		perror("fchmod");
}

void adjust_rights(const char *file)
{
	int fd = open(file, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", file, strerror(errno));
		return;
	}
	adjust_rights(fd);
	close(fd);
}

bool make_mailbox_hierarchy(const std::string &base) try
{
	for (const auto &subdir : {"", "/config", "/cid", "/eml", "/exmdb",
	     "/ext", "/tmp", "/tmp/imap.rfc822"}) {
		auto p = base + subdir;
		if (mkdir(p.c_str(), 0777) && errno != EEXIST) {
			fprintf(stderr, "E-1420: mkdir %s: %s\n", p.c_str(), strerror(errno));
			return false;
		}
		adjust_rights(p.c_str());
	}
	return true;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1625: ENOMEM\n");
	return false;
}

bool add_folderprop_iv(sqlite3_stmt *stmt, uint32_t art_num, bool add_next)
{
	const std::pair<uint32_t, uint32_t> tagvals[] = {
		{PR_DELETED_COUNT_TOTAL, 0},
		{PR_DELETED_FOLDER_COUNT, 0},
		{PR_HIERARCHY_CHANGE_NUM, 0},
		{PR_INTERNET_ARTICLE_NUMBER, art_num},
	};
	for (const auto &v : tagvals) {
		sqlite3_bind_int64(stmt, 1, v.first);
		sqlite3_bind_int64(stmt, 2, v.second);
		if (sqlite3_step(stmt) != SQLITE_DONE)
			return false;
		sqlite3_reset(stmt);
	}
	if (add_next) {
		sqlite3_bind_int64(stmt, 1, PROP_TAG_ARTICLENUMBERNEXT);
		sqlite3_bind_int64(stmt, 2, 1);
		if (sqlite3_step(stmt) != SQLITE_DONE)
			return false;
		sqlite3_reset(stmt);
	}
	return true;
}

bool add_folderprop_sv(sqlite3_stmt *stmt, const char *dispname,
    const char *contcls)
{
	const std::pair<uint32_t, const char *> tagvals[] =
		{{PR_DISPLAY_NAME, dispname}, {PR_COMMENT, ""}};
	for (const auto &v : tagvals) {
		sqlite3_bind_int64(stmt, 1, v.first);
		sqlite3_bind_text(stmt, 2, v.second, -1, SQLITE_STATIC);
		if (sqlite3_step(stmt) != SQLITE_DONE)
			return false;
		sqlite3_reset(stmt);
	}
	if (contcls != nullptr) {
		sqlite3_bind_int64(stmt, 1, PR_CONTAINER_CLASS);
		sqlite3_bind_text(stmt, 2, contcls, -1, SQLITE_STATIC);
		if (sqlite3_step(stmt) != SQLITE_DONE)
			return false;
		sqlite3_reset(stmt);
	}
	return true;
}

bool add_folderprop_tv(sqlite3_stmt *stmt)
{
	static constexpr uint32_t tags[] = {
		PR_CREATION_TIME, PR_LAST_MODIFICATION_TIME, PROP_TAG_HIERREV,
		PR_LOCAL_COMMIT_TIME_MAX,
	};
	uint64_t nt_time = rop_util_unix_to_nttime(time(nullptr));
	for (const auto proptag : tags) {
		sqlite3_bind_int64(stmt, 1, proptag);
		sqlite3_bind_int64(stmt, 2, nt_time);
		if (sqlite3_step(stmt) != SQLITE_DONE)
			return false;
		sqlite3_reset(stmt);
	}
	return true;
}

bool add_changenum(sqlite3_stmt *stmt, enum cnguid_type cng, uint64_t user_id,
    uint64_t change_num)
{
	XID xid{cng == CN_DOMAIN ? rop_util_make_domain_guid(user_id) :
	        rop_util_make_user_guid(user_id), change_num};
	uint8_t tmp_buff[24];
	EXT_PUSH ext_push;
	if (!ext_push.init(tmp_buff, sizeof(tmp_buff), 0) ||
	    ext_push.p_xid(xid) != EXT_ERR_SUCCESS)
		return false;
	sqlite3_bind_int64(stmt, 1, PR_CHANGE_KEY);
	sqlite3_bind_blob(stmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
	if (sqlite3_step(stmt) != SQLITE_DONE)
		return false;
	sqlite3_reset(stmt);
	PCL ppcl;
	if (!ppcl.append(xid))
		return false;
	auto pbin = ppcl.serialize();
	if (pbin == nullptr) {
		return false;
	}
	ppcl.clear();
	sqlite3_bind_int64(stmt, 1, PR_PREDECESSOR_CHANGE_LIST);
	sqlite3_bind_blob(stmt, 2, pbin->pb, pbin->cb, SQLITE_STATIC);
	if (sqlite3_step(stmt) != SQLITE_DONE) {
		rop_util_free_binary(pbin);
		return false;
	}
	rop_util_free_binary(pbin);
	sqlite3_reset(stmt);
	return true;
}

int mbop_truncate_chown(const char *tool, const char *file, bool force_overwrite)
{
	/*
	 * sqlite3_open does not expose O_EXCL, so let's create the file under
	 * EXCL semantics ahead of time.
	 */
	unsigned int flags = O_RDWR | O_CREAT | O_EXCL;
	if (force_overwrite) {
		flags &= ~O_EXCL;
		flags |= O_TRUNC;
	}
	auto fd = open(file, flags, S_IRUSR | S_IWUSR | S_IWGRP | S_IRGRP);
	if (fd >= 0) {
		adjust_rights(fd);
		close(fd);
	} else if (errno == EEXIST) {
		tool = HX_basename(tool);
		fprintf(stderr, "%s: %s already exists.\n", tool, file);
		fprintf(stderr, "%s: Use the -f option to force overwrite.\n", tool);
		return EEXIST;
	}
	return 0;
}

int mbop_insert_namedprops(sqlite3 *sdb, const char *datadir)
{
	std::vector<std::string> nplist;
	auto ret = list_file_read_fixedstrings("propnames.txt", datadir, nplist);
	if (ret == -ENOENT) {
		return 0;
	} else if (ret < 0) {
		printf("list_file_initd propnames.txt: %s\n", strerror(-ret));
		return ret;
	}
	auto stm = gx_sql_prep(sdb, "INSERT INTO `named_properties` VALUES (?, ?)");
	if (stm == nullptr)
		return -EIO;

	size_t i = 0;
	for (const auto &name : nplist) {
		uint16_t propid = 0x8001 + i++;
		if (propid >= 0xFFFF) {
			fprintf(stderr, "insert_namedprop: exhausted namedprop space\n");
			return -EIO;
		}
		stm.bind_int64(1, propid);
		stm.bind_text(2, name.c_str());
		ret = stm.step();
		if (ret != SQLITE_DONE) {
			fprintf(stderr, "insert_namedprop/sqlite3_step \"%s\": %s\n",
			        name.c_str(), sqlite3_errstr(ret));
			return -EIO;
		}
		stm.reset();
	}
	return 0;
}

int mbop_insert_storeprops(sqlite3 *sdb, const std::pair<uint32_t, uint64_t> *props)
{
	auto stm = gx_sql_prep(sdb, "INSERT INTO `store_properties` VALUES (?, ?)");
	if (stm == nullptr)
		return -EIO;
	for (const auto *e = props; e->first != 0; ++e) {
		stm.bind_int64(1, e->first);
		stm.bind_int64(2, e->second);
		auto ret = stm.step();
		if (ret != SQLITE_DONE) {
			fprintf(stderr, "insert_storeprops: step: %s\n", sqlite3_errstr(ret));
			return -EIO;
		}
		stm.reset();
	}
	return 0;
}

int mbop_slurp(const char *datadir, const char *file, std::string &sql_string)
{
	auto fp = fopen_sd(file, datadir);
	if (fp == nullptr) {
		int se = errno;
		fprintf(stderr, "fopen_sd %s: %s\n", file, strerror(errno));
		return -(errno = se);
	}
	size_t len = 0;
	auto data = HX_slurp_fd(fileno(fp.get()), &len);
	if (data != nullptr) {
		sql_string.append(data, len);
		free(data);
	}
	return 0;
}
