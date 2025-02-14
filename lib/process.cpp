// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2024 grommunio GmbH
// This file is part of Gromox.
#define _GNU_SOURCE 1 /* linux: gettid */
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <pthread.h>
#include <sched.h>
#include <string>
#include <thread>
#include <unistd.h>
#ifdef __GLIBC__
#	include <execinfo.h>
#endif
#if defined(__linux__) && defined(__GLIBC__) && __GLIBC__ == 2 && __GLIBC_MINOR__ >= 30
#	define HAVE_GLIBC_GETTID 1
#endif
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#ifdef __sun
#	include <sys/lwp.h>
#endif
#ifndef HAVE_GLIBC_GETTID
#	include <sys/syscall.h>
#endif
#ifdef __FreeBSD__
#	include <sys/sysctl.h>
#	include <sys/thr.h>
#	include <sys/types.h>
#endif
#include <libHX/io.h>
#include <libHX/proc.h>
#include <libHX/string.h>
#include <gromox/process.hpp>
#include <gromox/util.hpp>

namespace gromox {

static int gx_reexec_top_fd = -1;

errno_t filedes_limit_bump(size_t max)
{
	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
		int se = errno;
		mlog(LV_ERR, "getrlimit: %s", strerror(se));
		return se;
	}
	if (max == 0)
		max = rl.rlim_max;
	if (static_cast<size_t>(rl.rlim_cur) < max) {
		rl.rlim_cur = max;
		rl.rlim_max = max;
		if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
			int se = errno;
			mlog(LV_WARN, "setrlimit RLIMIT_NOFILE %zu: %s",
				max, strerror(se));
			return se;
		}
	}
	if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
		int se = errno;
		mlog(LV_ERR, "getrlimit: %s", strerror(se));
		return se;
	}
	mlog(LV_NOTICE, "system: maximum file descriptors: %zu",
		static_cast<size_t>(rl.rlim_cur));
	return 0;
}

/**
 * Give an approximate limit of how many threads make sense to run under the
 * current conditions.
 */
unsigned int gx_concurrency()
{
#if defined(__linux__) && defined(__GLIBC__)
	cpu_set_t set;
	CPU_ZERO_S(sizeof(set), &set);
	if (sched_getaffinity(0, sizeof(set), &set) == 0)
		return CPU_COUNT_S(sizeof(set), &set);
#endif
	return std::thread::hardware_concurrency();
}

unsigned long gx_gettid()
{
#ifdef HAVE_GLIBC_GETTID
	return gettid();
#elif defined(__linux__)
	return syscall(SYS_gettid);
#elif defined(__OpenBSD__)
	return getthrid();
#elif defined(__FreeBSD__)
	long z = 0;
	return thr_self(&z) == 0 ? z : (unsigned long)pthread_self();
#elif defined(__sun)
	return _lwp_self();
#else
	return (unsigned long)pthread_self();
#endif
}

/**
 * Upon setuid, tasks are restricted in their dumping (cf. linux/kernel/cred.c
 * in commit_creds, calling set_dumpable). To restore the dump flag, one could
 * use prctl, but re-executing the process has the benefit that the application
 * completely re-runs as unprivileged user from the start and can catch e.g.
 * file access errors that would occur before gx_reexec, and we can be sure
 * that privileged informationed does not escape into a dump.
 */
static errno_t gx_reexec(const char *const *argv) try
{
	auto s = getenv("GX_REEXEC_DONE");
	if (s != nullptr || argv == nullptr) {
		if (chdir("/") < 0)
			mlog(LV_ERR, "E-5312: chdir /: %s", strerror(errno));
		unsetenv("GX_REEXEC_DONE");
		unsetenv("HX_LISTEN_TOP_FD");
		unsetenv("LISTEN_FDS");
		return 0;
	}
	if (gx_reexec_top_fd >= 0)
		setenv("HX_LISTEN_TOP_FD", std::to_string(gx_reexec_top_fd + 1).c_str(), true);
	setenv("GX_REEXEC_DONE", "1", true);

#if defined(__linux__)
	hxmc_t *resolved = nullptr;
	auto ret = HX_readlink(&resolved, "/proc/self/exe");
	if (ret == -ENOENT) {
		mlog(LV_NOTICE, "reexec: readlink /proc/self/exe: %s; continuing without reexec-after-setuid, coredumps may be disabled", strerror(-ret));
		return 0;
	} else if (ret < 0) {
		mlog(LV_ERR, "reexec: readlink /proc/self/exe: %s", strerror(-ret));
		return -ret;
	}
	mlog(LV_INFO, "Reexecing %s", resolved);
	execv(resolved, const_cast<char **>(argv));
	int saved_errno = errno;
	perror("execv");
	HXmc_free(resolved);
	return saved_errno;
#elif defined(__FreeBSD__)
	std::string tgt;
	tgt.resize(64);
	int oid[] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1};
	while (true) {
		size_t z = tgt.size();
		auto ret = sysctl(oid, std::size(oid), tgt.data(), &z,
		           nullptr, 0);
		if (ret == 0) {
			tgt.resize(z);
			break;
		}
		if (errno != ENOMEM)
			return errno;
		tgt.resize(tgt.size() * 2);
	}
	mlog(LV_INFO, "Reexecing %s", tgt.c_str());
	execv(tgt.c_str(), const_cast<char **>(argv));
	int saved_errno = errno;
	perror("execv");
	return saved_errno;
#else
	/* Since none of our programs modify argv[0], executing the same should just work */
	mlog(LV_INFO, "Reexecing %s", argv[0]);
	execv(argv[0], const_cast<char **>(argv));
	int saved_errno = errno;
	perror("execv");
	return saved_errno;
#endif
} catch (const std::bad_alloc &) {
	return ENOMEM;
}

/**
 * Prepare a file descriptor so that it survives execve().
 * Sets a new upper bound on file descriptor numbers that need to be evaluated
 * on the next incarnation of the process.
 */
void gx_reexec_record(int new_fd)
{
	if (getenv("GX_REEXEC_DONE") != nullptr)
		return;
	for (int fd = gx_reexec_top_fd; fd <= new_fd; ++fd) {
		unsigned int flags = 0;
		socklen_t fz = sizeof(flags);
		if (fd < 0 || getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN,
		    &flags, &fz) != 0 || !flags)
			continue;
		flags = fcntl(fd, F_GETFD, 0) & ~FD_CLOEXEC;
		if (fcntl(fd, F_SETFD, flags) != 0)
			/* ignore */;
	}
	if (new_fd > gx_reexec_top_fd)
		gx_reexec_top_fd = new_fd;
}

/**
 * Start new thread with a big 16MB stack. Needed until high
 * consumers (gcc -fstack-usage) are eradicated.
 */
int pthread_create4(pthread_t *t, std::nullptr_t, void *(*f)(void *), void *a) noexcept
{
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	size_t tss = 0;
	auto ret = pthread_attr_getstacksize(&attr, &tss);
	if (ret == 0)
		tss = std::max(tss, static_cast<size_t>(16UL << 20));
	ret = pthread_attr_setstacksize(&attr, tss);
	if (ret != 0) {
		mlog(LV_ERR, "E-1135: pthread_attr_setstacksize: %s", strerror(ret));
		pthread_attr_destroy(&attr);
		return ret;
	}
	ret = pthread_create(t, &attr, f, a);
	pthread_attr_destroy(&attr);
	return ret;
}

/**
 * Make a few common signals non-fatal.
 */
int setup_signal_defaults()
{
	static int tab[] = {SIGALRM, SIGUSR1, SIGUSR2};
	for (auto signum : tab) {
		struct sigaction act;
		auto ret = sigaction(signum, nullptr, &act);
		if (ret < 0 || act.sa_handler != SIG_DFL)
			continue;
		sigemptyset(&act.sa_mask);
		act.sa_handler = [](int) {};
		ret = sigaction(signum, &act, nullptr);
		if (ret != 0)
			mlog(LV_ERR, "sigaction (%u): %s", signum, strerror(errno));
	}
	return 0;
}

std::string simple_backtrace()
{
	std::string out;
	/* Tried ILT's libbacktrace, but in practice it takes 500 ms per backtrace */
#ifdef __GLIBC__
	void *frame_ptrs[128];
	int num = backtrace(frame_ptrs, std::size(frame_ptrs));
	if (num == 0)
		return out;
	std::unique_ptr<char *[], stdlib_delete> names(backtrace_symbols(frame_ptrs, num));
	if (names == nullptr)
		return out;
	try {
		/* Frame 0 is simple_backtrace itself, skip it */
		for (int i = 1; i < num; ++i)
			out += std::string("<") + znul(HX_basename(names[i])) + ">";
	} catch (...) {
	}
#endif
	return out;
}

errno_t switch_user_exec(const char *user, char *const *argv)
{
	if (user == nullptr)
		user = RUNNING_IDENTITY;
	auto su_ret = HXproc_switch_user(user, nullptr);
	int se = errno;
	switch (su_ret) {
	case HXPROC_SU_NOOP: {
		auto ret = gx_reexec(nullptr);
		if (ret != 0)
			return ret;
		auto m = umask(07777);
		m = (m & ~0070) | ((m & 0700) >> 3); /* copy user bits to group bits */
		umask(m);
		return 0;
	}
	case HXPROC_SU_SUCCESS: {
		auto ret = gx_reexec(const_cast<const char *const *>(argv));
		if (ret != 0)
			return ret;
		auto m = umask(07777);
		m = (m & ~0070) | ((m & 0700) >> 3);
		umask(m);
		return 0;
	}
	case HXPROC_USER_NOT_FOUND:
		mlog(LV_ERR, "No such user \"%s\": %s", user, strerror(se));
		break;
	case HXPROC_GROUP_NOT_FOUND:
		mlog(LV_ERR, "Group lookup failed/Can't happen");
		break;
	case HXPROC_SETUID_FAILED:
		mlog(LV_ERR, "setuid to \"%s\" failed: %s", user, strerror(se));
		break;
	case HXPROC_SETGID_FAILED:
		mlog(LV_ERR, "setgid to groupof(\"%s\") failed: %s", user, strerror(se));
		break;
	case HXPROC_INITGROUPS_FAILED:
		mlog(LV_ERR, "initgroups for \"%s\" failed: %s", user, strerror(se));
		break;
	}
	return se;
}

}
