// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <libHX/proc.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_IOCTL_H
#	include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_VFS_H
#	include <sys/statfs.h>
#endif
#include <gromox/config_file.hpp>
#include <gromox/fileio.h>
#include <gromox/paths.h>

using namespace gromox;

enum class snapshot_mode {
	error, reflink, btrfs,
};

static unsigned int g_keep_months, g_keep_weeks, g_keep_days, g_keep_hours;
static std::string g_subvolume_root, g_snapshot_archive;
static constexpr cfg_directive snapshot_cfg_defaults[] = {
	{"retention_days", "7", CFG_SIZE},
	{"retention_hours", "0", CFG_SIZE},
	{"retention_months", "0", CFG_SIZE},
	{"retention_weeks", "4", CFG_SIZE},
	{"snapshot_archive", PKGSTATEDIR "-snapshots"},
	{"subvolume_root", PKGSTATEDIR},
	CFG_TABLE_END,
};

static errno_t reflink_supported(const std::string &src, const std::string &dst)
{
#ifdef __linux__
	gromox::tmpfile stf, dtf;
	wrapfd sfd(stf.open_anon(src.c_str(), O_RDWR, 0600));
	if (sfd.get() < 0)
		return errno;
	wrapfd dfd(dtf.open_anon(dst.c_str(), O_RDWR, 0600));
	if (dfd.get() < 0)
		return errno;
	if (ioctl(dfd.get(), _IOW(0x94, 9, int), sfd.get()) != 0)
		return errno;
	return 0;
#else
	return EOPNOTSUPP;
#endif
}

static enum snapshot_mode
snapshot_type(const std::string &root, const std::string &grpdir)
{
#ifdef __linux__
	struct statfs sb;
	if (statfs(root.c_str(), &sb) != 0) {
		fprintf(stderr, "statfs %s: %s\n", root.c_str(), strerror(errno));
		return snapshot_mode::error;
	}
	static constexpr auto btrfs_magic = 0x9123683eU;
	if (std::make_unsigned_t<decltype(sb.f_type)>(sb.f_type) == btrfs_magic)
		return snapshot_mode::btrfs;
	auto err = reflink_supported(root, grpdir);
	if (err != 0) {
		fprintf(stderr, "FICLONE support %s & %s: %s\n",
			root.c_str(), grpdir.c_str(), strerror(err));
		return snapshot_mode::error;
	}
	return snapshot_mode::reflink;
#else
	fprintf(stderr, "Don't know how to perform snapshots on this OS\n");
	return snapshot_mode::error;
#endif
}

static int do_snap(const std::string &grpdir, const char *today)
{
	auto sndir = grpdir + "/" + today;
	int fd = open(sndir.c_str(), O_RDONLY | O_DIRECTORY);
	if (fd >= 0) {
		/* Snapshot already existed, or something */
		close(fd);
		return EXIT_SUCCESS;
	} else if (errno != ENOENT) {
		fprintf(stderr, "stat %s: %s\n", sndir.c_str(), strerror(errno));
		return EXIT_FAILURE;
	}
	auto mode = snapshot_type(g_subvolume_root, grpdir);
	if (mode == snapshot_mode::error)
		return EXIT_FAILURE;
	printf("Creating %s\n", sndir.c_str());
	if (mode == snapshot_mode::btrfs) {
		const char *const a_btrfs[] = {
			"btrfs", "subvolume", "snapshot", "-r",
			g_subvolume_root.c_str(), sndir.c_str(), nullptr,
		};
		return HXproc_run_sync(a_btrfs, HXPROC_NULL_STDIN) == 0 ?
		       EXIT_SUCCESS : EXIT_FAILURE;
	}
	const char *const a_reflink[] = {
		"cp", "-a", "--reflink=always",
		g_subvolume_root.c_str(), sndir.c_str(), nullptr,
	};
	return HXproc_run_sync(a_reflink, HXPROC_NULL_STDIN) == 0 ?
	       EXIT_SUCCESS : EXIT_FAILURE;
}

static int do_purge(const char *grpdir, unsigned int mtime, unsigned int mmin)
{
	const char *time_type = mtime > 0 ? "-mtime" : "-mmin";
	char time_va[32];
	snprintf(time_va, sizeof(time_va), "+%u", mmin > 0 ? mmin : mtime);
	auto mode = snapshot_type(g_subvolume_root, grpdir);
	if (mode == snapshot_mode::error)
		return EXIT_FAILURE;
	if (mode == snapshot_mode::btrfs) {
		const char *const a_btrfs[] = {
			"find", grpdir, "-mindepth", "1", "-maxdepth", "1",
			"-type", "d", time_type, time_va, "-print", "-exec",
			"btrfs", "subvolume", "delete", "{}", "+", nullptr,
		};
		return HXproc_run_sync(a_btrfs, HXPROC_NULL_STDIN) == 0 ?
		       EXIT_SUCCESS : EXIT_FAILURE;
	}
	const char *const a_reflink[] = {
		"find", grpdir, "-mindepth", "1", "-maxdepth", "1",
		"-type", "d", time_type, time_va, "-print", "-exec",
		"rm", "-Rf", "{}", "+", nullptr,
	};
	return HXproc_run_sync(a_reflink, HXPROC_NULL_STDIN) == 0 ?
	       EXIT_SUCCESS : EXIT_FAILURE;
}

static int do_group(const char *gname, const char *today, unsigned int mtime,
    unsigned int mmin = 0)
{
	auto grpdir = g_snapshot_archive + "/" + gname;
	if (mkdir(grpdir.c_str(), S_IRUSR | S_IWUSR | S_IXUSR) != 0 &&
	    errno != EEXIST) {
		fprintf(stderr, "mkdir %s: %s\n", grpdir.c_str(), strerror(errno));
		return EXIT_FAILURE;
	}
	if (mtime != 0 || mmin != 0) {
		auto ret = do_snap(grpdir, today);
		if (ret != EXIT_SUCCESS)
			return ret;
	}
	printf("Purging %s...\n", gname);
	return do_purge(grpdir.c_str(), mtime, mmin);
}

int main(int argc, char **argv)
{
	setvbuf(stdout, nullptr, _IOLBF, 0);
	auto cfg = config_file_prg(nullptr, "snapshot.cfg", snapshot_cfg_defaults);
	if (cfg == nullptr)
		return EXIT_FAILURE;
	g_keep_months = cfg->get_ll("retention_months");
	g_keep_weeks = cfg->get_ll("retention_weeks");
	g_keep_days = cfg->get_ll("retention_days");
	g_keep_hours = cfg->get_ll("retention_hours");
	g_subvolume_root = cfg->get_value("subvolume_root");
	g_snapshot_archive = cfg->get_value("snapshot_archive");
	struct timespec tstamp[2];
	if (clock_gettime(CLOCK_REALTIME, &tstamp[0]) != 0) {
		perror("clock_gettime");
		return EXIT_FAILURE;
	}
	tstamp[1] = tstamp[0];
	auto tm = localtime(&tstamp[0].tv_sec);
	struct stat sb;
	if (stat(g_subvolume_root.c_str(), &sb) != 0 || !S_ISDIR(sb.st_mode) ||
	    stat(g_snapshot_archive.c_str(), &sb) != 0 || !S_ISDIR(sb.st_mode)) {
		fprintf(stderr, "Basic sanity check: %s or %s not a directory\n",
		        g_subvolume_root.c_str(), g_snapshot_archive.c_str());
		return EXIT_FAILURE;
	}
	/* Make subsequents snapshots carry a useful timestamp by touching the source now. */
	if (utimensat(AT_FDCWD, g_subvolume_root.c_str(), tstamp, 0) != 0) {
		fprintf(stderr, "utimensat %s: %s", g_subvolume_root.c_str(), strerror(errno));
		return EXIT_FAILURE;
	}

	char buf[32];
	strftime(buf, sizeof(buf), "%Y%m", tm);
	auto ret = do_group("monthly", buf, 31 * g_keep_months);
	if (ret != EXIT_SUCCESS)
		return ret;
	strftime(buf, sizeof(buf), "%YW%W", tm);
	ret = do_group("weekly", buf, 7 * g_keep_weeks);
	if (ret != EXIT_SUCCESS)
		return ret;
	strftime(buf, sizeof(buf), "%F", tm);
	ret = do_group("daily", buf, g_keep_days);
	if (ret != EXIT_SUCCESS)
		return ret;
	strftime(buf, sizeof(buf), "%FT%H", tm);
	ret = do_group("hourly", buf, 0, 60 * g_keep_hours);
	if (ret != EXIT_SUCCESS)
		return ret;
	return EXIT_SUCCESS;
}
