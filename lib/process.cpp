// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022–2026 grommunio GmbH
// This file is part of Gromox.
#define _GNU_SOURCE 1 /* linux: gettid */
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cassert>
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
#ifdef HAVE_SYS_EPOLL_H
#	include <sys/epoll.h>
#endif
#ifdef HAVE_SYS_EVENT_H
#	include <sys/event.h>
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
#include <libHX/socket.h>
#include <libHX/string.h>
#include <gromox/generic_connection.hpp>
#include <gromox/listener_ctx.hpp>
#include <gromox/poll_ctx.hpp>
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

poll_ctx::~poll_ctx()
{
	if (m_epfd >= 0)
		close(m_epfd);
}

void poll_ctx::reset()
{
	if (m_epfd >= 0) {
		close(m_epfd);
		m_epfd = -1;
	}
	m_events = {};
}

errno_t poll_ctx::init(int max_ev)
{
	if (m_epfd >= 0) {
		close(m_epfd);
		m_epfd = -1;
	}
	try {
#ifdef HAVE_SYS_EPOLL_H
		m_events.resize(max_ev);
#elif defined(HAVE_SYS_EVENT_H)
		/* READ-ready and WRITE-ready seems to be separately notified */
		m_events.resize(max_ev * 2);
#endif
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
		return ENOMEM;
	}
#ifdef HAVE_SYS_EPOLL_H
	m_epfd = epoll_create1(EPOLL_CLOEXEC);
	if (m_epfd < 0) {
		errno_t se = errno;
		mlog(LV_ERR, "poll_ctx::setup: epoll_create: %s", strerror(se));
		return se;
	}
#elif defined(HAVE_SYS_EVENT_H)
	m_epfd = kqueue();
	if (m_epfd < 0) {
		errno_t se = errno;
		mlog(LV_ERR, "poll_ctx::setup: kqueue: %s", strerror(se));
		return se;
	}
#endif
	return 0;
}

errno_t poll_ctx::addmod(unsigned int mask, int fd, void *ctx, bool add)
{
#ifdef HAVE_SYS_EPOLL_H
	struct epoll_event ev{};
	ev.data.ptr = ctx;
	if (mask & polling_read)
		ev.events |= EPOLLIN;
	if (mask & polling_write)
		ev.events |= EPOLLOUT;
	if (!(mask & level_trigger))
		ev.events |= EPOLLET | EPOLLONESHOT;
	auto ret = epoll_ctl(m_epfd, add ? EPOLL_CTL_ADD : EPOLL_CTL_MOD, fd, &ev);
#elif defined(HAVE_SYS_EVENT_H)
	unsigned int flags = (mask & level_trigger) ? EV_CLEAR : EV_ONESHOT;
	struct kevent ev[2]{};
	ev[0].ident = ev[1].ident = fd;
	ev[0].flags = ev[1].flags = EV_ADD | EV_ENABLE | flags;
	ev[0].udata = ev[1].udata = ctx;
	unsigned int nev = 0;
	if (mask & POLLING_READ)
		ev[nev++].filter = EVFILT_READ;
	if (mask & POLLING_WRITE)
		ev[nev++].filter = EVFILT_WRITE;
	auto ret = kevent(m_epfd, ev, nev, nullptr, 0, nullptr);
#endif
	if (ret == 0)
		return 0;
	errno_t se = errno;
	mlog(LV_ERR, "poll_ctx::%s: %s\n", add ? "add" : "mod", strerror(se));
	return se;
}

errno_t poll_ctx::del(int fd)
{
#ifdef HAVE_SYS_EPOLL_H
	auto ret = epoll_ctl(m_epfd, EPOLL_CTL_DEL, fd, nullptr);
#elif defined(HAVE_SYS_EVENT_H)
	struct kevent ev[2]{};
	EV_SET(&ev[0], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
	EV_SET(&ev[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
	auto ret = kevent(m_epfd, ev, std::size(ev), nullptr, 0, nullptr);
#endif
	if (ret == 0)
		return 0;
	errno_t se = errno;
	mlog(LV_ERR, "poll_ctx::del: %s\n", strerror(se));
	return se;
}

int poll_ctx::wait(const struct timespec *timeout, int max_ev)
{
	if (max_ev < 0 || static_cast<size_t>(max_ev) > m_events.size())
		max_ev = m_events.size();
#ifdef HAVE_SYS_EPOLL_H
	return epoll_pwait2(m_epfd, m_events.data(), max_ev, timeout, nullptr);
#elif defined(HAVE_SYS_EVENT_H)
	return kevent(m_epfd, nullptr, 0, m_events.data(), max_ev, timeout);
#endif
}

void *poll_ctx::data(unsigned int idx) const
{
#ifdef HAVE_SYS_EPOLL_H
	return idx < m_events.size() ? m_events[idx].data.ptr : nullptr;
#elif defined(HAVE_SYS_EVENT_H)
	return idx < m_events.size() ? m_events[idx].udata : nullptr;
#endif
}

void listener_ctx::reset()
{
	watch_stop();
	for (auto &e : m_sockets)
		close(e.fd);
	m_sockets.clear();
}

/**
 * @mark: an integer the caller can use to later recognize certain sockets again
 *        (e.g. unencrypted vs. Implicit TLS)
 */
errno_t listener_ctx::add_inet(const char *addr, uint16_t port, uint32_t mark)
{
	auto fd = HX_inet_listen(addr, port);
	if (fd < 0) {
		auto se = errno;
		mlog(LV_ERR, "%s([%s]:%hu): %s", __PRETTY_FUNCTION__, addr, port, strerror(se));
		return se;
	}
	try {
		m_sockets.emplace_back(fd, mark);
	} catch (const std::bad_alloc &) {
		close(fd);
		mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
		return ENOMEM;
	}
	gx_reexec_record(fd);
	return 0;
}

/**
 * Wait on sockets and invoke a callback on new incoming connections.
 *
 * @stop: an extern variable to also evaluate when to stop accepting
 * @cb:   callback when a connection has been accept()ed
 *
 * @cb shall return 0 if processing should continue normally. Any other value
 * causes loop_fptr to return with that value. This way, @cb too can induce a
 * temporary exit from the loop.
 *
 * loop_f returns 0 when stopping normally, -1 on error, and otherwise whatever
 * @cb returned.
 *
 * NOTE: Because the signal handler for e.g. SIGINT may run in a completely
 * unrelated thread, epoll_wait may not get interrupted at all. For this
 * reason, most main() functions have a sleeping loop that evaluates @stop and
 * then specifically pthread_kill()s any children [such as listener_thread],
 * which then also stops epoll_wait.
 */
void *listener_ctx::listener_thread(void *thread_arg)
{
	auto &lctx = *static_cast<listener_ctx *>(thread_arg);
	if (lctx.m_thread_name.size() > 0)
		pthread_setname_np(pthread_self(), lctx.m_thread_name.c_str());

	while (!*lctx.m_stop) {
		auto ready = lctx.m_poller.wait();
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			return nullptr;
		}
		for (int i = 0; i < ready; ++i) {
			auto sd = static_cast<socket_desc *>(lctx.m_poller.data(i));
			assert(sd != nullptr);
			auto conn = generic_connection::accept(sd->fd, lctx.m_haproxy_level, lctx.m_stop);
			if (conn.sockd == -2)
				return 0; /* stop signalled */
			if (conn.sockd < 0)
				continue;
			conn.mark = sd->mark;
			lctx.m_callback(std::move(conn));
		}
	}
	return nullptr;
}

errno_t listener_ctx::watch_start(gromox::atomic_bool &stop,
    int (*cb)(generic_connection &&)) try
{
	watch_stop();
	if (m_sockets.size() == 0)
		return 0;
	m_stop = &stop;
	m_callback = cb;
	auto err = m_poller.init(m_sockets.size());
	if (err != 0)
		return err;
	for (auto &entry : m_sockets) {
		err = m_poller.add(poll_ctx::polling_read | poll_ctx::level_trigger,
		      entry.fd, &entry);
		if (err != 0) {
			m_poller.reset();
			return err;
		}
	}
	auto ret = pthread_create4(&m_thr_id, nullptr, listener_thread, this);
	if (ret != 0) {
		m_poller.reset();
		mlog(LV_ERR, "%s: pthread_create: %s", __PRETTY_FUNCTION__, strerror(ret));
		return ret;
	}
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return ENOMEM;
}

void listener_ctx::watch_stop()
{
	if (!pthread_equal(m_thr_id, {})) {
		pthread_kill(m_thr_id, SIGALRM);
		pthread_join(m_thr_id, nullptr);
		m_thr_id = {};
	}
	m_poller.reset();
}

}
