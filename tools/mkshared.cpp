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
#include <unistd.h>
#include <utility>
#include <sys/stat.h>
#include <gromox/mapidefs.h>
#include <gromox/proptags.hpp>
#include "mkshared.hpp"

void adjust_rights(int fd)
{
	uid_t uid = -1;
	gid_t gid = -1;
	unsigned int mode = S_IRUSR | S_IWUSR;
	auto sp = getpwnam("gromox");
	if (sp != nullptr)
		uid = sp->pw_uid;
	auto gr = getgrnam("gromox");
	if (gr != nullptr) {
		gid = gr->gr_gid;
		mode |= S_IRGRP | S_IWGRP;
	}
	if (fchown(fd, uid, gid) < 0)
		perror("fchown");
	if (fchmod(fd, mode) < 0)
		perror("fchmod");
}

void adjust_rights(const char *file)
{
	int fd = open(file, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open %s O_RDWR: %s\n", file, strerror(errno));
		return;
	}
	adjust_rights(fd);
	close(fd);
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

bool add_folderprop_tv(sqlite3_stmt *stmt, uint64_t nt_time)
{
	static constexpr uint32_t tags[] = {
		PR_CREATION_TIME, PR_LAST_MODIFICATION_TIME, PROP_TAG_HIERREV,
		PR_LOCAL_COMMIT_TIME_MAX,
	};
	for (const auto proptag : tags) {
		sqlite3_bind_int64(stmt, 1, proptag);
		sqlite3_bind_int64(stmt, 2, nt_time);
		if (sqlite3_step(stmt) != SQLITE_DONE)
			return false;
		sqlite3_reset(stmt);
	}
	return true;
}
