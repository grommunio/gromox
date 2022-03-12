// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2021-2022 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#define _GNU_SOURCE 1 /* unistd.h:environ */
#include <cerrno>
#include <csignal>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <list>
#include <memory>
#include <spawn.h>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>
#include <vector>
#if __linux__ && defined(HAVE_SYS_RANDOM_H)
#	include <sys/random.h>
#endif
#include <libHX/ctype_helper.h>
#include <libHX/io.h>
#include <libHX/proc.h>
#include <libHX/string.h>
#include <sys/wait.h>
#include <gromox/config_file.hpp>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>

class hxmc_deleter {
	public:
	void operator()(hxmc_t *s) { HXmc_free(s); }
};

using namespace gromox;

static int gx_reexec_top_fd = -1;

LIB_BUFFER::LIB_BUFFER(size_t isize, size_t inum) :
	item_size(isize), max_items(inum)
{
	if (isize == 0 || inum == 0)
		fprintf(stderr, "E-1669: Invalid parameters passed to LIB_BUFFER ctor\n");
}

LIB_BUFFER &LIB_BUFFER::operator=(LIB_BUFFER &&o) noexcept
{
	allocated_num += o.allocated_num.load(); /* allow freeing previous takes */
	o.allocated_num = 0;
	item_size = o.item_size;
	max_items = o.max_items;
	return *this;
}

void *LIB_BUFFER::get_raw()
{
	do {
		auto exp = allocated_num.load();
		if (exp >= max_items) {
			errno = ENOMEM;
			return nullptr;
		}
		auto des = exp + 1;
		if (allocated_num.compare_exchange_strong(exp, des))
			break;
	} while (true);
	auto ptr = malloc(item_size);
	if (ptr == nullptr)
		--allocated_num;
	return ptr;
}

void LIB_BUFFER::put_raw(void *item)
{
	free(item);
	--allocated_num;
}

char **read_file_by_line(const char *file)
{
	std::unique_ptr<FILE, file_deleter> fp(fopen(file, "r"));
	if (fp == nullptr)
		return nullptr;

	hxmc_t *line = nullptr;
	try {
		std::list<std::unique_ptr<char[], stdlib_delete>> dq;
		while (HX_getl(&line, fp.get()) != nullptr) {
			HX_chomp(line);
			decltype(dq)::value_type s(strdup(line));
			if (s == nullptr)
				return nullptr;
			dq.push_back(std::move(s));
		}
		HXmc_free(line);
		line = nullptr;
		auto ret = me_alloc<char *>(dq.size() + 1);
		if (ret == nullptr)
			return ret;
		size_t i = 0;
		for (auto &e : dq)
			ret[i++] = e.release();
		return ret;
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return nullptr;
	} catch (...) {
		HXmc_free(line);
		throw;
	}
}

int gx_vsnprintf1(char *buf, size_t sz, const char *file, unsigned int line,
    const char *fmt, va_list args)
{
	auto ret = vsnprintf(buf, sz, fmt, args);
	if (ret < 0) {
		*buf = '\0';
		return ret;
	} else if (static_cast<size_t>(ret) >= sz) {
		fprintf(stderr, "gx_vsnprintf: truncation at %s:%u (%d bytes into buffer of %zu)\n",
		        file, line, ret, sz);
		return strlen(buf);
	}
	return ret;
}

int gx_snprintf1(char *buf, size_t sz, const char *file, unsigned int line,
    const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	auto ret = gx_vsnprintf1(buf, sz, file, line, fmt, args);
	va_end(args);
	if (ret < 0) {
		*buf = '\0';
		return ret;
	} else if (static_cast<size_t>(ret) >= sz) {
		fprintf(stderr, "gx_snprintf: truncation at %s:%u (%d bytes into buffer of %zu)\n",
		        file, line, ret, sz);
		return strlen(buf);
	}
	return ret;
}

namespace {

struct popen_fdset {
	int in[2] = {-1, -1}, out[2] = {-1, -1}, err[2] = {-1, -1}, null = -1;

	popen_fdset() = default;
	~popen_fdset()
	{
		if (in[0] != -1) close(in[0]);
		if (in[1] != -1) close(in[1]);
		if (out[0] != -1) close(out[0]);
		if (out[1] != -1) close(out[1]);
		if (err[0] != -1) close(err[0]);
		if (err[1] != -1) close(err[1]);
		if (null != -1) close(null);
	}
	NOMOVE(popen_fdset);
};

}

namespace gromox {

pid_t popenfd(const char *const *argv, int *fdinp, int *fdoutp,
    int *fderrp, const char *const *env)
{
	if (argv == nullptr || argv[0] == nullptr)
		return -EINVAL;

	popen_fdset fd;
	if (fdinp == nullptr || fdoutp == nullptr || fderrp == nullptr) {
		fd.null = open("/dev/null", O_RDWR);
		if (fd.null < 0)
			return -errno;
	}
	posix_spawn_file_actions_t fa{};
	auto ret = posix_spawn_file_actions_init(&fa);
	if (ret != 0)
		return -ret;
	auto cl2 = make_scope_exit([&]() { posix_spawn_file_actions_destroy(&fa); });

	/* Close child-unused ends of the pipes; move child-used ends to fd 0-2. */
	if (fdinp != nullptr) {
		if (pipe(fd.in) < 0)
			return -errno;
		ret = posix_spawn_file_actions_addclose(&fa, fd.in[1]);
		if (ret != 0)
			return -ret;
		ret = posix_spawn_file_actions_adddup2(&fa, fd.in[0], STDIN_FILENO);
		if (ret != 0)
			return -ret;
	} else {
		ret = posix_spawn_file_actions_adddup2(&fa, fd.null, STDIN_FILENO);
		if (ret != 0)
			return -ret;
	}

	if (fdoutp != nullptr) {
		if (pipe(fd.out) < 0)
			return -errno;
		ret = posix_spawn_file_actions_addclose(&fa, fd.out[0]);
		if (ret != 0)
			return -ret;
		ret = posix_spawn_file_actions_adddup2(&fa, fd.out[1], STDOUT_FILENO);
		if (ret != 0)
			return -ret;
	} else {
		ret = posix_spawn_file_actions_adddup2(&fa, fd.null, STDOUT_FILENO);
		if (ret != 0)
			return -ret;
	}

	if (fderrp == nullptr) {
		ret = posix_spawn_file_actions_adddup2(&fa, fd.null, STDERR_FILENO);
		if (ret != 0)
			return -ret;
	} else if (fderrp == fdoutp) {
		ret = posix_spawn_file_actions_adddup2(&fa, fd.out[1], STDERR_FILENO);
		if (ret != 0)
			return -ret;
	} else {
		if (fderrp != nullptr && fderrp != fdoutp && pipe(fd.err) < 0)
			return -errno;
		ret = posix_spawn_file_actions_addclose(&fa, fd.err[0]);
		if (ret != 0)
			return -ret;
		ret = posix_spawn_file_actions_adddup2(&fa, fd.err[1], STDERR_FILENO);
		if (ret != 0)
			return -ret;
	}

	/* Close all pipe ends that were not already fd 0-2. */
	if (fd.in[0] != -1 && fd.in[0] != STDIN_FILENO &&
	    (ret = posix_spawn_file_actions_addclose(&fa, fd.in[0])) != 0)
		return -ret;
	if (fderrp != fdoutp) {
		if (fd.out[1] != -1 && fd.out[1] != STDOUT_FILENO &&
		    (ret = posix_spawn_file_actions_addclose(&fa, fd.out[1])) != 0)
			return -ret;
		if (fd.err[1] != -1 && fd.err[1] != STDERR_FILENO &&
		    (ret = posix_spawn_file_actions_addclose(&fa, fd.err[1])) != 0)
			return -ret;
	} else {
		if (fd.out[1] != -1 && fd.out[1] != STDOUT_FILENO &&
		    fd.out[1] != STDERR_FILENO &&
		    (ret = posix_spawn_file_actions_addclose(&fa, fd.out[1])) != 0)
			return -ret;
	}
	if (fd.null != -1 && fd.null != STDIN_FILENO &&
	    fd.null != STDOUT_FILENO && fd.null != STDERR_FILENO &&
	    (ret = posix_spawn_file_actions_addclose(&fa, fd.null)) != 0)
		return -ret;

	pid_t pid = -1;
	ret = posix_spawnp(&pid, argv[0], &fa, nullptr, const_cast<char **>(argv), const_cast<char **>(env));
	if (ret != 0)
		return -ret;
	if (fdinp != nullptr) {
		*fdinp = fd.in[1];
		fd.in[1] = -1;
	}
	if (fdoutp != nullptr) {
		*fdoutp = fd.out[0];
		fd.out[0] = -1;
	}
	if (fderrp != nullptr && fderrp != fdoutp) {
		*fderrp = fd.err[0];
		fd.err[0] = -1;
	}
	return pid;
}

ssize_t feed_w3m(const void *inbuf, size_t len, std::string &outbuf) try
{
	std::string filename;
	auto tmpdir = getenv("TMPDIR");
	filename = tmpdir == nullptr ? "/tmp" : tmpdir;
	auto pos = filename.length();
	filename += "/XXXXXXXXXXXX.html";
	randstring_k(&filename[pos+1], 12, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	filename[pos+13] = '.';

	struct xclose { void operator()(FILE *f) { fclose(f); } };
	std::unique_ptr<FILE, xclose> fp(fopen(filename.c_str(), "w"));
	if (fp == nullptr || fwrite(inbuf, len, 1, fp.get()) != 1)
		return -1;
	auto cl1 = make_scope_exit([&]() { unlink(filename.c_str()); });
	fp.reset();
	int fout = -1;
	auto cl2 = make_scope_exit([&]() { if (fout != -1) close(fout); });
	const char *const argv[] = {"w3m", "-dump", filename.c_str(), nullptr};
	auto pid = popenfd(argv, nullptr, &fout, nullptr, const_cast<const char *const *>(environ));
	if (pid < 0)
		return -1;
	int status = 0;
	auto cl3 = make_scope_exit([&]() { waitpid(pid, &status, 0); });
	outbuf = std::string();
	ssize_t ret;
	char fbuf[4096];
	while ((ret = read(fout, fbuf, GX_ARRAY_SIZE(fbuf))) > 0)
		outbuf.append(fbuf, ret);
	return WIFEXITED(status) ? outbuf.size() : -1;
} catch (...) {
	return -1;
}

/*
 * Trim "<foo>" from string, and make two C strings from it,
 * each with a trailing \0, and each being preprended with
 * Pascal-style length byte which incidentally also counts the \0.
 * \r\n is appended.
 * "hi <who>, give" -> 4 h i space \0 9 , space g i v e \r \n \0
 */
std::string resource_parse_stcode_line(const char *src)
{
	std::string out;
	uint8_t srclen = strlen(src);
	out.reserve(srclen + 6);
	auto ptr = strchr(src, '<');
	if (ptr == nullptr || ptr == src) {
		uint8_t sub = srclen + 3;
		out.append(reinterpret_cast<char *>(&sub), 1);
		out.append(src, srclen);
		out.append("\r\n", 3);
		return out;
	}
	uint8_t seg = ptr - src + 1;
	out.append(reinterpret_cast<char *>(&seg), 1);
	out.append(src, seg - 1);
	out += '\0';
	ptr = strchr(src, '>');
	if (ptr == nullptr)
		return "\006OMG\r\n";
	++ptr;
	seg = strlen(ptr) + 3;
	out.append(reinterpret_cast<char *>(&seg), 1);
	out.append(ptr);
	out.append("\r\n", 2);
	return out;
}

static constexpr struct {
	const char *suffix = nullptr;
	unsigned int len = 0, mult = 0;
} time_suffix[] = {
	{"seconds", 7, 1},
	{"second", 6, 1},
	{"sec", 3, 1},
	{"s", 1, 1},
	{"minutes", 7, 60},
	{"minute", 6, 60},
	{"min", 3, 60},
	{"m", 1, 60},
	{"hours", 5, 3600},
	{"hour", 4, 3600},
	{"h", 1, 3600},
	{"days", 4, 86400},
	{"day", 3, 86400},
	{"d", 1, 86400},
};

long atoitvl(const char *s)
{
	long result = 0;
	do {
		while (HX_isspace(*s))
			++s;
		if (*s == '\0')
			break;
		unsigned int mult = 0;
		char *end;
		auto v = strtoul(s, &end, 10);
		if (s == end)
			return -1;
		s = end;
		while (HX_isspace(*s))
			++s;
		if (*s == '\0')
			mult = 1; /* assume seconds */
		for (const auto &e : time_suffix) {
			if (strncmp(s, e.suffix, e.len) == 0) {
				mult = e.mult;
				s += e.len;
				break;
			}
		}
		if (mult == 0)
			return -1;
		result += v * mult;
	} while (true);
	return result;
}

bool parse_bool(const char *s)
{
	if (s == nullptr)
		return false;
	char *end = nullptr;
	if (strtoul(s, &end, 0) == 0 && *end == '\0')
		return false;
	if (strcasecmp(s, "no") == 0 || strcasecmp(s, "off") == 0 ||
	    strcasecmp(s, "false") == 0)
		return false;
	return true;
}

std::string bin2hex(const void *vin, size_t len)
{
	std::string buffer;
	if (vin == nullptr)
		return buffer;
	static constexpr char digits[] = "0123456789abcdef";
	auto input = static_cast<const char *>(vin);
	buffer.resize(len * 2);
	for (size_t j = 0; len-- > 0; j += 2) {
		buffer[j]   = digits[(*input >> 4) & 0x0F];
		buffer[j+1] = digits[*input & 0x0F];
		++input;
	}
	return buffer;
}

std::string hex2bin(const char *input)
{
	auto max = strlen(input) / 2; /* ignore last nibble if needed */
	std::string buf;
	buf.resize(max);
	for (size_t n = 0; n < max; ++n) {
		unsigned char c = HX_tolower(input[2*n]);
		unsigned char d = HX_tolower(input[2*n+1]);
		if (c >= '0' && c <= '9')
			c -= '0';
		else if (c >= 'A' && c <= 'F')
			c -= 'A' + 10;
		else
			c = 0;
		if (d >= '0' && d <= '9')
			d -= '0';
		else if (d >= 'A' && d <= 'F')
			d -= 'A' + 10;
		else
			d = 0;
		buf[n] = (c << 4) | d;
	}
	return buf;
}

void rfc1123_dstring(char *buf, size_t z, time_t ts)
{
	if (ts == 0)
		ts = time(nullptr);
	struct tm tm;
	gmtime_r(&ts, &tm);
	strftime(buf, z, "%a, %d %b %Y %T GMT", &tm);
}

void startup_banner(const char *prog)
{
	fprintf(stderr, "\n%s %s (pid %ld uid %ld)\n\n", prog, PACKAGE_VERSION,
	        static_cast<long>(getpid()), static_cast<long>(getuid()));
}

/**
 * Upon setuid, tasks are restricted in their dumping (cf. linux/kernel/cred.c
 * in commit_creds, calling set_dumpable). To restore the dump flag, one could
 * use prctl, but re-executing the process has the benefit that the application
 * completely re-runs as unprivileged user from the start and can catch e.g.
 * file access errors that would occur before gx_reexec, and we can be sure
 * that privileged informationed does not escape into a dump.
 */
int gx_reexec(const char *const *argv)
{
	auto s = getenv("GX_REEXEC_DONE");
	if (s != nullptr || argv == nullptr) {
		chdir("/");
		unsetenv("GX_REEXEC_DONE");
		unsetenv("HX_LISTEN_TOP_FD");
		unsetenv("LISTEN_FDS");
		return 0;
	}
	if (gx_reexec_top_fd >= 0) {
		char topfd[16];
		snprintf(topfd, arsizeof(topfd), "%d", gx_reexec_top_fd + 1);
		setenv("HX_LISTEN_TOP_FD", topfd, true);
	}
	setenv("GX_REEXEC_DONE", "1", true);

	hxmc_t *resolved = nullptr;
	auto ret = HX_readlink(&resolved, "/proc/self/exe");
	if (ret < 0) {
		fprintf(stderr, "reexec: readlink: %s", strerror(-ret));
		return ret;
	}
	fprintf(stderr, "Reexecing %s\n", resolved);
	execv(resolved, const_cast<char **>(argv));
	int saved_errno = errno;
	perror("execv");
	HXmc_free(resolved);
	return -saved_errno;
}

void gx_reexec_record(int fd)
{
	if (fd > gx_reexec_top_fd)
		gx_reexec_top_fd = fd;
}

int switch_user_exec(const CONFIG_FILE &cf, const char **argv)
{
	auto user = cf.get_value("running_identity");
	if (user == nullptr)
		user = "gromox";
	switch (HXproc_switch_user(user, nullptr)) {
	case HXPROC_SU_NOOP:
		return gx_reexec(nullptr);
	case HXPROC_SU_SUCCESS:
		return gx_reexec(argv);
	case HXPROC_USER_NOT_FOUND:
		fprintf(stderr, "No such user \"%s\": %s\n", user, strerror(errno));
		break;
	case HXPROC_GROUP_NOT_FOUND:
		fprintf(stderr, "Group lookup failed/Can't happen\n");
		break;
	case HXPROC_SETUID_FAILED:
		fprintf(stderr, "setuid to \"%s\" failed: %s\n", user, strerror(errno));
		break;
	case HXPROC_SETGID_FAILED:
		fprintf(stderr, "setgid to groupof(\"%s\") failed: %s\n", user, strerror(errno));
		break;
	case HXPROC_INITGROUPS_FAILED:
		fprintf(stderr, "initgroups for \"%s\" failed: %s\n", user, strerror(errno));
		break;
	}
	return -errno;
}

int setup_sigalrm()
{
	struct sigaction act;
	sigaction(SIGALRM, nullptr, &act);
	if (act.sa_handler != SIG_DFL)
		return 0;
	sigemptyset(&act.sa_mask);
	act.sa_handler = [](int) {};
	return sigaction(SIGALRM, &act, nullptr);
}

}
