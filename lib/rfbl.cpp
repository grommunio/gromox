// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2021-2022 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cerrno>
#include <csignal>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <iconv.h>
#include <istream>
#include <list>
#include <memory>
#include <shared_mutex>
#include <spawn.h>
#include <sstream>
#include <streambuf>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>
#include <vector>
#include <zstd.h>
#ifdef HAVE_SYSLOG_H
#	include <syslog.h>
#endif
#include <sys/stat.h>
#if defined(HAVE_SYS_XATTR_H)
#	include <sys/xattr.h>
#endif
#include <json/reader.h>
#include <json/writer.h>
#include <libHX/ctype_helper.h>
#include <libHX/io.h>
#include <libHX/proc.h>
#include <libHX/string.h>
#include <sys/wait.h>
#ifdef __FreeBSD__
#	include <sys/types.h>
#	include <sys/sysctl.h>
#endif
#include <gromox/config_file.hpp>
#include <gromox/fileio.h>
#include <gromox/json.hpp>
#include <gromox/mapidefs.h>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/socket.h>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>
#include <gromox/xarray2.hpp>

using namespace std::string_literals;
using namespace gromox;

extern "C" {
extern char **environ;
}

namespace {

class hxmc_deleter {
	public:
	void operator()(hxmc_t *s) const { HXmc_free(s); }
};

}

static unsigned int g_max_loglevel = LV_NOTICE;
static std::shared_mutex g_log_mutex;
static std::unique_ptr<FILE, file_deleter> g_logfp;
static bool g_log_direct = true, g_log_tty, g_log_syslog;

LIB_BUFFER::LIB_BUFFER(size_t isize, size_t inum, const char *name,
    const char *hint) :
	item_size(isize), max_items(inum), m_name(name), m_hint(hint)
{
	if (isize == 0 || inum == 0)
		mlog(LV_ERR, "E-1669: Invalid parameters passed to LIB_BUFFER ctor");
}

LIB_BUFFER &LIB_BUFFER::operator=(LIB_BUFFER &&o) noexcept
{
	allocated_num += o.allocated_num.load(); /* allow freeing previous takes */
	o.allocated_num = 0;
	item_size = o.item_size;
	max_items = o.max_items;
	m_name = o.m_name;
	m_hint = o.m_hint;
	return *this;
}

void *LIB_BUFFER::get_raw()
{
	do {
		auto exp = allocated_num.load();
		if (exp >= max_items) {
			mlog(LV_ERR, "E-1992: The buffer pool \"%s\" is full. "
			        "This either means a memory leak, or the pool sizes "
			        "have been configured too low.",
			        znul(m_name));
			if (m_hint != nullptr)
				mlog(LV_INFO, "I-1993: Config directives that could be tuned: %s", m_hint);
			else
				mlog(LV_INFO, "I-1994: Size is dynamic but not tunable.");
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

errno_t read_file_by_line(const char *file, std::vector<std::string> &out)
{
	std::unique_ptr<FILE, file_deleter> fp(fopen(file, "r"));
	if (fp == nullptr)
		return errno;

	hxmc_t *line = nullptr;
	try {
		while (HX_getl(&line, fp.get()) != nullptr) {
			HX_chomp(line);
			out.emplace_back(line);
		}
		HXmc_free(line);
		return 0;
	} catch (const std::bad_alloc &) {
		HXmc_free(line);
		return ENOMEM;
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
		mlog(LV_ERR, "gx_vsnprintf: truncation at %s:%u (%d bytes into buffer of %zu)",
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
		mlog(LV_ERR, "gx_snprintf: truncation at %s:%u (%d bytes into buffer of %zu)",
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
	randstring(&filename[pos+1], 12, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	filename[pos+13] = '.';

	std::unique_ptr<FILE, file_deleter> fp(fopen(filename.c_str(), "w"));
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
 * each with a trailing \0, and each being prepended with
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
		/* This \0 here terminates the first fragment.. */
		out.append("\r\n", 3);
		/*
		 * The implicit trailing \0 in std::string serves as the length
		 * byte for the second fragment.
		 */
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

std::string bin2txt(const void *vdata, size_t len)
{
	auto data = static_cast<const unsigned char *>(vdata);
	std::string ret;
	char b[5];
	for (size_t i = 0; i < len; ++i) {
		if (isprint(data[i]) && data[i] != '"' &&
		    data[i] != '\'' && data[i] != '\\') {
			/*
			 * Facilitate inclusion in string literals - and not
			 * messing up in-editor coloring.
			 */
			b[0] = data[i];
			b[1] = '\0';
		} else if (data[i] < 0010) {
			b[0] = '\\';
			b[1] = '0' + (data[i] % 8);
			b[2] = '\0';
		} else if (data[i] < 0100) {
			b[0] = '\\';
			b[1] = '0' + (data[i] / 8 % 8);
			b[2] = '0' + (data[i] % 8);
			b[3] = '\0';
		} else {
			b[0] = '\\';
			b[1] = '0' + (data[i] / 64 % 8);
			b[2] = '0' + (data[i] / 8 % 8);
			b[3] = '0' + (data[i] % 8);
			b[4] = '\0';
		}
		ret.append(b);
	}
	return ret;
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

std::string hex2bin(std::string_view input, hex2bin_mode onbad)
{
	auto max = input.size() / 2;
	size_t z = 0;
	std::string buf;
	buf.resize(max);
	while (input.size() > 0) {
		unsigned char hi = 0, lo = 0;
		while (input.size() > 0) {
			hi = HX_tolower(input[0]);
			if (hi >= '0' && hi <= '9') {
				hi -= '0';
			} else if (hi >= 'a' && hi <= 'f') {
				hi = hi - 'a' + 10;
			} else if (onbad == HEX2BIN_SKIP) {
				input.remove_prefix(1);
				continue;
			} else if (onbad == HEX2BIN_ZERO) {
				hi = 0;
			} else if (onbad == HEX2BIN_STOP) {
				return buf;
			} else if (onbad == HEX2BIN_EMPTY) {
				return buf = {};
			}
			input.remove_prefix(1);
			break;
		}
		if (input.size() == 0)
			break;
		while (input.size() > 0) {
			lo = HX_tolower(input[0]);
			if (lo >= '0' && lo <= '9') {
				lo -= '0';
			} else if (lo >= 'a' && lo <= 'f') {
				lo = lo - 'a' + 10;
			} else if (onbad == HEX2BIN_SKIP) {
				input.remove_prefix(1);
				continue;
			} else if (onbad == HEX2BIN_ZERO) {
				lo = 0;
			} else if (onbad == HEX2BIN_STOP) {
				buf.resize(z);
				return buf;
			} else if (onbad == HEX2BIN_EMPTY) {
				return buf = {};
			}
			input.remove_prefix(1);
			break;
		}
		buf[z++] = (hi << 4) | lo;
	}
	buf.resize(z);
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
	fprintf(stderr, "\n");
	mlog(LV_NOTICE, "%s %s (pid %ld uid %ld)", prog, PACKAGE_VERSION,
	        static_cast<long>(getpid()), static_cast<long>(getuid()));
	fprintf(stderr, "\n");
}

/**
 * Upon setuid, tasks are restricted in their dumping (cf. linux/kernel/cred.c
 * in commit_creds, calling set_dumpable). To restore the dump flag, one could
 * use prctl, but re-executing the process has the benefit that the application
 * completely re-runs as unprivileged user from the start and can catch e.g.
 * file access errors that would occur before gx_reexec, and we can be sure
 * that privileged informationed does not escape into a dump.
 */
errno_t gx_reexec(const char *const *argv) try
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

#if defined(__linux__)
	hxmc_t *resolved = nullptr;
	auto ret = HX_readlink(&resolved, "/proc/self/exe");
	if (ret < 0) {
		mlog(LV_ERR, "reexec: readlink: %s", strerror(-ret));
		return -ret;
	}
	mlog(LV_NOTICE, "Reexecing %s", resolved);
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
	mlog(LV_NOTICE, "Reexecing %s", tgt.c_str());
	execv(tgt.c_str(), const_cast<char **>(argv));
	int saved_errno = errno;
	perror("execv");
	return saved_errno;
#else
	/* Since none of our programs modify argv[0], executing the same should just work */
	mlog(LV_NOTICE, "Reexecing %s", argv[0]);
	execv(argv[0], const_cast<char **>(argv));
	int saved_errno = errno;
	perror("execv");
	return saved_errno;
#endif
} catch (const std::bad_alloc &) {
	return ENOMEM;
}

errno_t switch_user_exec(const CONFIG_FILE &cf, const char **argv)
{
	auto user = cf.get_value("running_identity");
	if (user == nullptr)
		user = RUNNING_IDENTITY;
	switch (HXproc_switch_user(user, nullptr)) {
	case HXPROC_SU_NOOP:
		return gx_reexec(nullptr);
	case HXPROC_SU_SUCCESS:
		return gx_reexec(argv);
	case HXPROC_USER_NOT_FOUND:
		mlog(LV_ERR, "No such user \"%s\": %s", user, strerror(errno));
		break;
	case HXPROC_GROUP_NOT_FOUND:
		mlog(LV_ERR, "Group lookup failed/Can't happen");
		break;
	case HXPROC_SETUID_FAILED:
		mlog(LV_ERR, "setuid to \"%s\" failed: %s", user, strerror(errno));
		break;
	case HXPROC_SETGID_FAILED:
		mlog(LV_ERR, "setgid to groupof(\"%s\") failed: %s", user, strerror(errno));
		break;
	case HXPROC_INITGROUPS_FAILED:
		mlog(LV_ERR, "initgroups for \"%s\" failed: %s", user, strerror(errno));
		break;
	}
	return errno;
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

void safe_memset(void *p, uint8_t c, size_t z)
{
	volatile size_t vz = 0;
	volatile auto q = static_cast<uint8_t *>(p);
	if (z != 0) do {
		memset(p, c, z);
	} while (q[vz] != c);
}

unsigned int newline_size(const char *s, size_t z)
{
	if (z >= 1 && s[0] == '\n')
		return 1;
	if (z >= 2 && s[0] == '\r' && s[1] == '\n')
		return 2;
	return 0;
}

bool cu_validate_msgclass(const char *k)
{
	/* MS-OXCSTOR v25 §2.2.1.2ff */
	auto z = strlen(k);
	if (z + 1 > 255 || k[0] == '.' || (z > 0 && k[z-1] == '.'))
		return false;
	for (size_t i = 0; i < z; ++i) {
		if (k[i] < 0x20 || k[i] > 0x7E)
			return false;
		if (k[i] == '.' && k[i+1] == '.')
			return false;
	}
	return true;
}

bool cpid_cstr_compatible(uint32_t cpid)
{
	if (cpid == CP_UTF16 || cpid == CP_UTF16BE ||
	    cpid == CP_UTF32 || cpid == CP_UTF32BE) {
		mlog(LV_ERR, "E-2103: CString conversion routine called with cpid %u", cpid);
		return false;
	}
	return true;
}

bool cset_cstr_compatible(const char *s)
{
	if (strncasecmp(s, "utf16", 5) == 0 || strncasecmp(s, "utf32", 5) == 0 ||
	    strncasecmp(s, "utf-16", 6) == 0 || strncasecmp(s, "utf-32", 6) == 0) {
		mlog(LV_ERR, "E-2104: CString conversion routine called with charset %s", s);
		return false;
	}
	return true;
}

/**
 * Return an upper bound of bytes needed to represent an arbitrary MBCS string
 * @s, with trailing NUL, as UTF-8. @s must be C string compatible, so it won't
 * be UTF-16/32; but it could be UTF-8 already.
 */
size_t mb_to_utf8_len(const char *s)
{
	/*
	 * The assumption here is that all classic codepages won't map
	 * something to outside the Basic Multilingual Plane.
	 */
	return 3 * strlen(s) + 1;
}

/**
 * Return an upper bound of bytes needed to represent the UTF-8 string @s (with
 * its trailing NUL character) in some other MBCS.
 */
size_t utf8_to_mb_len(const char *s)
{
	auto z = strlen(s);
	auto utf32 = 4 * z + 4;
	/*
	 * Shift states... yuck. Anyway, if you look at all values of @utf32,
	 * @isojp and @utf7, @utf32 is always largest, which means we need not
	 * calculate max(utf32,utf7,isojp).
	 */
	// auto isojp = (z + 1) / 4 * 9 - 1 + (z - 3) % 4 + 1;
	// auto utf7  = (z + 1) / 2 * 6 - (z % 2) + 1;
	return utf32;
}

/**
 * Return an upper bound of bytes needed to represent the UTF-8 string @s (with
 * its trailing NUL character) as UTF-16.
 */
size_t utf8_to_utf16_len(const char *s)
{
	return 2 * strlen(s) + 2;
}

int iconv_validate()
{
	for (const auto s : {"UTF-7", "UTF-16LE", "UNICODE", "windows-1252",
	     "iso-8859-1", "iso-2022-jp"}) {
		auto k = iconv_open("UTF-8", "UTF-16LE");
		if (k == (iconv_t)-1) {
			mlog(LV_ERR, "I can't work like this! iconv lacks support for the essential character set %s. "
			        "Perhaps you need to install some libc locale package.", s);
			return -errno;
		}
		iconv_close(k);
	}
	return 0;
}

bool get_digest(const char *json, const char *key, char *out, size_t outmax) try
{
	Json::Value jval;
	if (!gromox::json_from_str(json, jval))
		return false;
	if (!jval.isMember(key))
		return false;
	auto &memb = jval[key];
	if (memb.isString())
		gx_strlcpy(out, memb.asCString(), outmax);
	else
		gx_strlcpy(out, memb.asString().c_str(), outmax);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1988: ENOMEM");
	return false;
}

template<typename T> static bool
set_digest2(char *json, size_t iomax, const char *key, T &&val) try
{
	Json::Value jval;
	if (!gromox::json_from_str(json, jval))
                return false;
	jval[key] = val;
	Json::StreamWriterBuilder swb;
	swb["indentation"] = "";
	gx_strlcpy(json, Json::writeString(swb, std::move(jval)).c_str(), iomax);
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1989: ENOMEM");
	return false;
}

bool set_digest(char *json, size_t iomax, const char *key, const char *val)
{
	return set_digest2(json, iomax, key, val);
}

bool set_digest(char *json, size_t iomax, const char *key, uint64_t val)
{
	/*
	 * jsoncpp 1.7 has an ambiguous conversion at
	 * `jval[key]=val`, so force a particular json type now.
	 */
	return set_digest2(json, iomax, key, Json::Value::UInt64(val));
}

int open_tmpfile(const char *dir, std::string *fullname, unsigned int flags,
    unsigned int mode) try
{
	int fd;
	if (fullname != nullptr)
		fullname->clear();
#ifdef O_TMPFILE
	fd = open(dir, O_TMPFILE | flags, mode);
	if (fd >= 0)
		return fd;
	if (errno != EISDIR && errno != EOPNOTSUPP)
		return -errno;
#endif
	char tn[17];
	randstring(tn, 16, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
	std::string tf;
	if (fullname == nullptr)
		fullname = &tf;
	*fullname = dir + "/"s + tn;
	fd = open(fullname->c_str(), O_CREAT | flags, mode);
	if (fd >= 0)
		return fd;
	return -errno;
} catch (const std::bad_alloc &) {
	return -ENOMEM;
}

void mlog_init(const char *filename, unsigned int max_level)
{
	g_max_loglevel = max_level;
	g_log_direct = filename == nullptr || *filename == '\0' || strcmp(filename, "-") == 0;
	g_log_syslog = filename != nullptr && strcmp(filename, "syslog") == 0;
	g_log_tty    = isatty(STDERR_FILENO);
	if (g_log_direct && getppid() == 1 && getenv("JOURNAL_STREAM") != nullptr)
		g_log_syslog = true;
	if (g_log_syslog) {
		openlog(nullptr, LOG_PID, LOG_MAIL);
		setlogmask((1 << (max_level + 2)) - 1);
		return;
	}
	if (g_log_direct) {
		setvbuf(stderr, nullptr, _IOLBF, 0);
		return;
	}
	std::lock_guard hold(g_log_mutex);
	g_logfp.reset(fopen(filename, "a"));
	g_log_direct = g_logfp == nullptr;
	if (g_log_direct) {
		mlog(LV_ERR, "Could not open %s for writing: %s. Using stderr.",
		        filename, strerror(errno));
		setvbuf(stderr, nullptr, _IOLBF, 0);
	} else {
		setvbuf(g_logfp.get(), nullptr, _IOLBF, 0);
	}
}

void mlog(unsigned int level, const char *fmt, ...)
{
	if (level > g_max_loglevel)
		return;
	va_list args;
	va_start(args, fmt);
	if (g_log_syslog) {
		vsyslog(level + 1, fmt, args);
		va_end(args);
		return;
	} else if (g_log_direct) {
		if (g_log_tty)
			fprintf(stderr,
				level <= LV_ERR ? "\e[1;31m" :
				level <= LV_WARN ? "\e[31m" :
				level <= LV_NOTICE ? "\e[1;37m" :
				level == LV_DEBUG ? "\e[1;30m" : "");
		vfprintf(stderr, fmt, args);
		if (g_log_tty)
			fprintf(stderr, "\e[0m");
		fputc('\n', stderr);
		va_end(args);
		return;
	}
	char buf[64];
	buf[0] = '<';
	buf[1] = '0' + level;
	buf[2] = '>';
	auto now = time(nullptr);
	struct tm tmbuf;
	strftime(buf + 3, std::size(buf) - 3, "%FT%T ", localtime_r(&now, &tmbuf));
	std::shared_lock hold(g_log_mutex);
	fputs(buf, g_logfp.get());
	vfprintf(g_logfp.get(), fmt, args);
	fputc('\n', g_logfp.get());
	va_end(args);
}

errno_t wrapfd::close_rd() noexcept
{
	if (m_fd < 0)
		return 0;
	auto ret = ::close(m_fd);
	m_fd = -1;
	if (ret == 0)
		return 0;
	ret = errno;
	try {
		mlog(LV_ERR, "wrapfd::close: %s", strerror(ret));
	} catch (...) {
	}
	return ret;
}

std::string zstd_decompress(std::string_view x)
{
	std::string out;
	auto strm = ZSTD_createDStream();
	if (strm == nullptr)
		throw std::bad_alloc();
	auto cl_0 = make_scope_exit([&]() { ZSTD_freeDStream(strm); });
	ZSTD_initDStream(strm);
	ZSTD_inBuffer xds = {x.data(), x.size()};
	size_t ffsize = ZSTD_getFrameContentSize(x.data(), x.size());
	if (ffsize == ZSTD_CONTENTSIZE_ERROR)
		return out;
	if (ffsize == ZSTD_CONTENTSIZE_UNKNOWN)
		ffsize = 0;
	else if (ffsize < out.capacity())
		/* Offer the entire on-stack room in the first iteration */
		ffsize = out.capacity();
	if (ffsize == 0)
		ffsize = ZSTD_DStreamOutSize();
	out.resize(ffsize);
	ZSTD_outBuffer outds = {out.data(), out.size()};

	while (xds.pos < xds.size) {
		auto ret = ZSTD_decompressStream(strm, &outds, &xds);
		if (ZSTD_isError(ret))
			break;
		if (outds.pos == outds.size) {
			outds.size = out.size() * 2;
			out.resize(outds.size);
			outds.dst = out.data();
		}
	}
	out.resize(outds.pos);
	return out;
}

size_t gx_decompressed_size(const char *infile)
{
	wrapfd fd(open(infile, O_RDONLY));
	if (fd.get() < 0)
		return errno == ENOENT ? SIZE_MAX : 0;
	struct stat sb;
	if (fstat(fd.get(), &sb) < 0 || !S_ISREG(sb.st_mode))
		return 0;
	size_t inbufsize = ZSTD_DStreamInSize();
	if (static_cast<unsigned long long>(sb.st_size) < inbufsize)
		inbufsize = sb.st_size;
	auto inbuf = std::make_unique<char[]>(inbufsize);
	auto rdret = read(fd.get(), inbuf.get(), inbufsize);
	if (rdret < 0)
		return 0;
	auto outsize = ZSTD_getFrameContentSize(inbuf.get(), rdret);
	if (outsize == ZSTD_CONTENTSIZE_ERROR)
		return 0;
	else if (outsize == ZSTD_CONTENTSIZE_UNKNOWN)
		return sb.st_size;
	return outsize;
}

/**
 * Even if this function returns an error, outbin.pv needs to be freed.
 */
errno_t gx_decompress_file(const char *infile, BINARY &outbin,
    void *(*alloc)(size_t), void *(*realloc)(void *, size_t)) try
{
	outbin = {};
	wrapfd fd(open(infile, O_RDONLY));
	if (fd.get() < 0)
		return errno;
	struct stat sb;
	if (fstat(fd.get(), &sb) < 0)
		return errno;
	if (!S_ISREG(sb.st_mode))
		return 0;

	auto strm = ZSTD_createDStream();
	if (strm == nullptr)
		throw std::bad_alloc();
	auto cl_0 = make_scope_exit([&]() { ZSTD_freeDStream(strm); });
	ZSTD_initDStream(strm);

	size_t inbufsize = ZSTD_DStreamInSize();
	if (static_cast<unsigned long long>(sb.st_size) < inbufsize)
		inbufsize = sb.st_size;
	auto inbuf = std::make_unique<char[]>(inbufsize);
	auto rdret = read(fd.get(), inbuf.get(), inbufsize);
	if (rdret < 0)
		return errno;
#if defined(HAVE_POSIX_FADVISE)
	if (posix_fadvise(fd.get(), 0, sb.st_size, POSIX_FADV_SEQUENTIAL) != 0)
		/* ignore */;
#endif

	auto outsize = ZSTD_getFrameContentSize(inbuf.get(), rdret);
	if (outsize == ZSTD_CONTENTSIZE_ERROR)
		return EIO;
	else if (outsize == ZSTD_CONTENTSIZE_UNKNOWN)
		outsize = 1023;
	else if (outsize == 0)
		outsize = 1; /* so that multiplication later on works */
	if (outsize >= UINT32_MAX - 1)
		outsize = UINT32_MAX - 1;
	outbin.pv = alloc(outsize + 1); /* arrange for \0 */
	if (outbin.pv == nullptr)
		return ENOMEM;
	outbin.cb = outsize;

	ZSTD_inBuffer inds = {inbuf.get(), static_cast<size_t>(rdret)};
	ZSTD_outBuffer outds = {outbin.pv, outbin.cb};
	do {
		/*
		 * Repeat decompress attempt of current read buffer for as long
		 * as output buffer is not big enough.
		 */
		while (inds.pos < inds.size) {
			auto zret = ZSTD_decompressStream(strm, &outds, &inds);
			if (ZSTD_isError(zret)) {
				mlog(LV_ERR, "ZSTD_decompressStream %s: %s",
					infile, ZSTD_getErrorName(zret));
				return EIO;
			}
			if (zret == 0)
				/* One frame is done; but there may be more in @inds. */
				continue;
			if (outds.pos < outds.size)
				continue;
			if (outbin.cb >= UINT32_MAX - 1)
				return EFBIG;
			size_t newsize = outbin.cb < UINT32_MAX / 2 ? outbin.cb * 2 : UINT32_MAX - 1;
			void *newblk = realloc(outbin.pv, newsize + 1);
			if (newblk == nullptr)
				return ENOMEM;
			outbin.cb  = newsize;
			outbin.pv  = newblk;
			outds.size = newsize;
			outds.dst  = newblk;
		}
		/*
		 * Read next bite from compressed file.
		 * There could be more zstd frames.
		 */
		rdret = read(fd.get(), inbuf.get(), inbufsize);
		if (rdret < 0)
			return errno;
		inds.pos = 0;
		inds.size = static_cast<size_t>(rdret);
	} while (rdret != 0);
	outbin.cb = outds.pos;
	outbin.pb[outbin.cb] = '\0';
	return 0;
} catch (const std::bad_alloc &) {
	return ENOMEM;
}

errno_t gx_compress_tofile(std::string_view inbuf, const char *outfile, uint8_t complvl)
{
	wrapfd fd(open(outfile, O_WRONLY | O_TRUNC | O_CREAT, 0666));
	if (fd.get() < 0)
		return errno;
	if (complvl == 0)
		/* Our default is even more important than zstd's own default */
		complvl = 6;
#ifdef HAVE_FSETXATTR
	if (fsetxattr(fd.get(), "btrfs.compression", "none", 4, XATTR_CREATE) != 0)
		/* ignore */;
#endif

	auto strm = ZSTD_createCStream();
	auto cl_0 = make_scope_exit([&]() { ZSTD_freeCStream(strm); });
	ZSTD_initCStream(strm, complvl);
	ZSTD_CCtx_setParameter(strm, ZSTD_c_checksumFlag, 1);
	ZSTD_CCtx_setPledgedSrcSize(strm, inbuf.size());
	ZSTD_inBuffer inds = {inbuf.data(), inbuf.size()};
	ZSTD_outBuffer outds{};
	outds.size = std::min(ZSTD_CStreamOutSize(), static_cast<size_t>(SSIZE_MAX));
	auto outbuf = std::make_unique<char[]>(ZSTD_CStreamOutSize());
	outds.dst = outbuf.get();

	while (inds.pos < inds.size) {
		outds.pos = 0;
		auto zr = ZSTD_compressStream2(strm, &outds, &inds, ZSTD_e_continue);
		if (ZSTD_isError(zr))
			return EIO;
		auto r2 = HXio_fullwrite(fd.get(), outds.dst, outds.pos);
		if (r2 < 0 || static_cast<size_t>(r2) != outds.pos)
			return EIO;
	}
	while (true) {
		outds.pos = 0;
		auto zr = ZSTD_compressStream2(strm, &outds, &inds, ZSTD_e_end);
		if (ZSTD_isError(zr))
			return EIO;
		auto r2 = HXio_fullwrite(fd.get(), outds.dst, outds.pos);
		if (r2 < 0 || static_cast<size_t>(r2) != outds.pos)
			return EIO;
		if (zr == 0)
			break;
	}
	return fd.close_wr();
}

struct iomembuf : public std::streambuf {
	iomembuf(const char *p, size_t z) {
		auto q = const_cast<char *>(p);
		setg(q, q, q + z);
	}
};

struct imemstream : public virtual iomembuf, public std::istream {
	imemstream(const char *p, size_t z) :
		iomembuf(p, z),
		std::istream(static_cast<std::streambuf *>(this))
	{}
};

bool json_from_str(std::string_view sv, Json::Value &jv)
{
	imemstream strm(sv.data(), sv.size());
	return Json::parseFromStream(Json::CharReaderBuilder(),
	       strm, &jv, nullptr);
}

}

int XARRAY::append(MITEM &&ptr, unsigned int tag) try
{
	if (tag == 0 || get_itemx(tag) != nullptr)
		return -1;
	do {
		auto exp = m_limit.load();
		if (exp == 0) {
			mlog(LV_ERR, "E-1995: XARRAY pool exhausted");
			return -1;
		}
		auto nuval = exp - 1;
		if (m_limit.compare_exchange_strong(exp, nuval))
			break;
	} while (true);
	m_hash.emplace(tag, m_vec.size());
	try {
		m_vec.push_back(std::move(ptr));
	} catch (const std::bad_alloc &) {
		m_hash.erase(tag);
		++m_limit;
		return -1;
	}
	return 0;
} catch (const std::bad_alloc &) {
	++m_limit;
	return -1;
}

void XARRAY::clear()
{
	auto z = m_vec.size();
	m_vec.clear();
	m_hash.clear();
	m_limit += z;
}

XARRAY::~XARRAY()
{
	m_limit += m_vec.size();
}
