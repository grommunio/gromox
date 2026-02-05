// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021–2026 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <iconv.h>
#include <memory>
#include <netdb.h>
#include <spawn.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <zstd.h>
#include <libHX/defs.h>
#include <libHX/endian.h>
#include <libHX/io.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#if defined(HAVE_SYS_XATTR_H)
#	include <sys/xattr.h>
#endif
#include <gromox/archive.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/paths.h>
#include <gromox/util.hpp>

using namespace std::string_literals;
using namespace gromox;

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

archive::~archive()
{
	if (mapped_area != nullptr)
		munmap(deconst(mapped_area), mapped_size);
}

errno_t archive::open(const char *file)
{
	wrapfd fd(::open(file, O_RDONLY | O_BINARY));
	if (fd.get() < 0)
		return errno;
	struct stat sb;
	if (fstat(fd.get(), &sb) < 0)
		return errno;
	if (mapped_area != nullptr)
		munmap(deconst(mapped_area), mapped_size);
	mapped_size = sb.st_size;
	mapped_area = static_cast<char *>(mmap(nullptr, mapped_size, PROT_READ, MAP_SHARED, fd.get(), 0));
	if (mapped_area == (void *)-1)
		return errno;
	if (memcmp(mapped_area, "PACK", 4) != 0 || mapped_size < 12)
		return EINVAL;
	auto dirofs  = le32p_to_cpu(&mapped_area[4]);
	auto dirsize = le32p_to_cpu(&mapped_area[8]) / 64;
	if (dirofs + dirsize > mapped_size)
		return EINVAL;
	entries.clear();
	for (unsigned int i = 0; i < dirsize; ++i) {
		auto deofs = dirofs + 64 * i;
		auto entryofs = std::min(le32p_to_cpu(&mapped_area[deofs+56]), static_cast<uint32_t>(UINT32_MAX));
		auto entrysz  = std::min(le32p_to_cpu(&mapped_area[deofs+60]), static_cast<uint32_t>(UINT32_MAX));
		std::string_view name(&mapped_area[deofs], strnlen(&mapped_area[deofs], 56));
		std::string_view data(&mapped_area[entryofs], entrysz);
		entries.emplace(std::move(name), std::move(data));
	}
	return 0;
}

const std::string_view *archive::find(const std::string &file) const
{
	auto i = entries.find(file);
	return i == entries.cend() ? nullptr : &i->second;
}

/**
 * Routine intended for programs:
 *
 * Read user-specified config file (@ov) or, if that is unset, try the default file
 * (@fb, located in default searchpaths) in silent mode.
 */
std::shared_ptr<CONFIG_FILE> config_file_prg(const char *ov, const char *fb,
    const cfg_directive *key_desc)
{
	if (ov == nullptr)
		return config_file_initd(fb, PKGSYSCONFDIR, key_desc);
	auto cfg = config_file_init(ov, key_desc);
	if (cfg == nullptr)
		mlog(LV_ERR, "config_file_init %s: %s", ov, strerror(errno));
	return cfg;
}

BOOL config_file::save()
{
	if (!m_touched)
		return TRUE;
	std::unique_ptr<FILE, file_deleter> fp(fopen(m_filename.c_str(), "w"));
	if (fp == nullptr) {
		fprintf(stderr, "config_file.save %s: %s\n", m_filename.c_str(), strerror(errno));
		return false;
	}
	for (const auto &kv : m_vars)
		fprintf(fp.get(), "%s = %s\n", kv.first.c_str(), kv.second.m_val.c_str());
	return TRUE;
}

void tmpfile::close()
{
	if (m_fd < 0)
		return;
	::close(m_fd);
	m_fd = -1;
	if (m_path.empty())
		return;
	if (::remove(m_path.c_str()) < 0 && errno != ENOENT)
		mlog(LV_ERR, "E-2902: remove %s: %s", m_path.c_str(), strerror(errno));
	m_path.clear();
}

int tmpfile::open_anon(const char *dir, unsigned int flags, unsigned int mode)
{
#if defined(O_TMPFILE)
	return open_impl(dir, flags, mode, true);
#else
	return open_impl(dir, flags, mode, false);
#endif
}

int tmpfile::open_linkable(const char *dir, unsigned int flags, unsigned int mode)
{
	return open_impl(dir, flags, mode, false);
}

int tmpfile::open_impl(const char *dir, unsigned int flags, unsigned int mode,
    bool make_anon) try
{
	close();
#ifdef O_TMPFILE
	if (make_anon) {
		m_path.clear();
		m_fd = ::open(dir, O_TMPFILE | flags, mode);
		if (m_fd >= 0)
			return m_fd;
		if (errno != EISDIR && errno != EOPNOTSUPP)
			return -errno;
	}
#endif
	char tn[17];
	randstring(tn, 16, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
	m_path = dir + "/"s + tn;
	m_fd = ::open(m_path.c_str(), O_CREAT | flags, mode);
	return m_fd >= 0 ? m_fd : -errno;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return -ENOMEM;
}

errno_t tmpfile::link_to_overwrite(const char *newpath)
{
	if (m_path.empty())
		return EINVAL;
	if (m_fd < 0)
		return EBADF;
	/*
	 * write()+rename() could succeed and only close() could return ENOSPC.
	 * This breaks the tmpfile class's goal for atomic placement of
	 * files-with-content. Call fsync as a remedy.
	 */
	if (::fsync(m_fd) < 0)
		return errno;
	if (::rename(m_path.c_str(), newpath) != 0)
		return errno;
	m_path.clear();
	return 0;
}

errno_t tmpfile::link_to_noreplace(const char *newpath)
{
	if (m_path.empty())
		return EINVAL;
	if (m_fd < 0)
		return EBADF;
	if (::fsync(m_fd) < 0)
		return errno;
#ifdef HAVE_RENAMEAT2
	if (renameat2(AT_FDCWD, m_path.c_str(), AT_FDCWD, newpath, RENAME_NOREPLACE) == 0) {
		m_path.clear();
		return 0;
	}
#endif
	/*
	 * If we land here, renameat2 is not implemented for the particular
	 * filesystem.
	 *
	 * renameat2 guarantees that at most one name will exist at any one
	 * time. We do not need this guarantee. The file is just for this class
	 * instsance. The "noreplace" logic can be implemented with link+unlink
	 * instead. If unlink fails because the fs cannot allocate space to
	 * start a transaction for unlink(), so be it.
	 */
	if (::link(m_path.c_str(), newpath) != 0)
		return errno;
	if (::unlink(m_path.c_str()) != 0)
		/* ignore */;
	m_path.clear();
	return 0;
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
	return (errno = ret);
}

namespace gromox {

errno_t canonical_hostname(std::string &out) try
{
	char buf[UDOM_SIZE];
	if (gethostname(buf, std::size(buf)) != 0)
		return errno;
	if (strchr(buf, '.') != nullptr) {
		out = buf;
		return 0;
	}
	static constexpr struct addrinfo hints = {AI_CANONNAME};
	struct addrinfo *aires = nullptr;
	mlog(LV_DEBUG, "my_hostname: canonicalization of hostname \"%s\"...", buf);
	auto err = getaddrinfo(buf, nullptr, &hints, &aires);
	if (err != 0) {
		mlog(LV_ERR, "getaddrinfo %s: %s", buf, gai_strerror(err));
		return EINVAL;
	}
	auto cl_0 = HX::make_scope_exit([&]() { freeaddrinfo(aires); });
	out = aires->ai_canonname;
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ENOMEM;
}

std::unique_ptr<FILE, file_deleter> fopen_sd(const char *filename, const char *sdlist)
{
	if (sdlist == nullptr || strchr(filename, '/') != nullptr)
		return std::unique_ptr<FILE, file_deleter>(fopen(filename, "r"));
	try {
		for (auto &&dir : gx_split(sdlist, ':')) {
			errno = 0;
			auto full = std::move(dir) + "/" + filename;
			std::unique_ptr<FILE, file_deleter> fp(fopen(full.c_str(), "r"));
			if (fp != nullptr)
				return fp;
			if (errno != ENOENT) {
				mlog(LV_ERR, "fopen_sd %s: %s",
				        full.c_str(), strerror(errno));
				return nullptr;
			}
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return nullptr;
	}
	return nullptr;
}

DIR_mp opendir_sd(const char *dirname, const char *sdlist)
{
	DIR_mp dn;
	if (sdlist == nullptr || strchr(dirname, '/') != nullptr) {
		dn.m_path = dirname;
		dn.m_dir.reset(opendir(dirname));
		return dn;
	}
	for (auto &&dir : gx_split(sdlist, ':')) {
		errno = 0;
		dn.m_path = std::move(dir) + "/" + dirname;
		dn.m_dir.reset(opendir(dn.m_path.c_str()));
		if (dn.m_dir != nullptr)
			return dn;
		if (errno != ENOENT) {
			mlog(LV_ERR, "opendir_sd %s: %s",
			        dn.m_path.c_str(), strerror(errno));
			return dn;
		}
	}
	dn.m_path.clear();
	return dn;
}

pid_t popenfd(const char *const *argv, int *fdinp, int *fdoutp,
    int *fderrp, const char *const *env)
{
	if (argv == nullptr || argv[0] == nullptr)
		return -EINVAL;

	popen_fdset fd;
	if (fdinp == nullptr || fdoutp == nullptr || fderrp == nullptr) {
		fd.null = ::open("/dev/null", O_RDWR);
		if (fd.null < 0)
			return -errno;
	}
	posix_spawn_file_actions_t fa{};
	auto ret = posix_spawn_file_actions_init(&fa);
	if (ret != 0)
		return -ret;
	auto cl2 = HX::make_scope_exit([&]() { posix_spawn_file_actions_destroy(&fa); });

	/* Close child-unused ends of the pipes; move child-used ends to fd 0-2. */
	if (fdinp != nullptr) {
		if (::pipe(fd.in) < 0)
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
		if (::pipe(fd.out) < 0)
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
		if (fderrp != nullptr && fderrp != fdoutp && ::pipe(fd.err) < 0)
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

/**
 * @fp:       file to emit to
 * @src:      input data
 * @cset:     character set of data in @src
 *
 * Convert @src to UTF-8 if needed (depends on @cset), and writeout to @fp.
 * Updates @cset in case w3m should not be given the -I argument.
 * Returns 0 for success; other values indicate an error condition.
 */
static int utf8_writeout(FILE *fp, const void *vsrc, size_t src_size, const char *&cset)
{
	auto src = const_cast<char *>(static_cast<const char *>(vsrc));
	if (cset == nullptr || strcasecmp(cset, "utf8") == 0 ||
	    strcasecmp(cset, "utf-8") == 0)
		return fwrite(src, src_size, 1, fp) == 1 ? 0 : -1;
	auto cd = iconv_open("utf-8", cset);
	if (cd == iconv_t(-1)) {
		/* Dunno how to translate, just feed it as-is to w3m */
		cset = nullptr;
		return 0;
	}
	auto cleanup = HX::make_scope_exit([&]() { iconv_close(cd); });
	char buffer[4096];

	/* Loop copied from iconvtext() */
	while (src_size > 0) {
		auto dst = buffer;
		size_t dst_size = sizeof(buffer);
		auto ret = iconv(cd, &src, &src_size, &dst, &dst_size);
		if (ret != static_cast<size_t>(-1) || dst_size != sizeof(buffer)) {
			if (fwrite(buffer, sizeof(buffer) - dst_size, 1, fp) != 1)
				return -1;
			continue;
		}
		if (src_size > 0) {
			--src_size;
			++src;
		}
		if (fwrite(buffer, sizeof(buffer) - dst_size, 1, fp) != 1)
			return -1;
	}

	/* Flush pending shift and/or state */
	auto dst = buffer;
	size_t dst_size = sizeof(buffer);
	auto ret = iconv(cd, nullptr, 0, &dst, &dst_size);
	if (ret == static_cast<size_t>(-1))
		/* ignore */;
	if (dst_size != sizeof(buffer) &&
	    fwrite(buffer, sizeof(buffer) - dst_size, 1, fp) != 1)
		return -1;
	return 0;
}

/**
 * Run an external HTML-to-text converter.
 *
 * @inbuf:  input data
 * @cset:   character set of input data (overriding any <meta> tag
 *          inside the data), or %nullptr if unknown
 * @outbuf: result variable for caller
 *
 * It is valid for @inbuf to point to the same object as @outbuf.
 * Returns 0 on success, negative non-zero on error with errno set.
 * @outbuf is only replaced on success.
 */
int feed_w3m(std::string_view inbuf, const char *cset, std::string &final_buf) try
{
	std::string filename;
	auto tmpdir = getenv("TMPDIR");
	filename = tmpdir == nullptr ? "/tmp" : tmpdir;
	auto pos = filename.length();
	filename += "/XXXXXXXXXXXX.html";
	randstring(&filename[pos+1], 12, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	filename[pos+13] = '.';

	std::unique_ptr<FILE, file_deleter> fp(fopen(filename.c_str(), "w"));
	if (fp == nullptr)
		return -1;
	auto cl1 = HX::make_scope_exit([&]() { unlink(filename.c_str()); });
	if (utf8_writeout(fp.get(), inbuf.data(), inbuf.size(), cset) != 0)
		return -1;
	fp.reset();
	int fout = -1;
	auto cl2 = HX::make_scope_exit([&]() { if (fout != -1) close(fout); });
	const char *argv[8];
	int argc = 0;
	argv[argc++] = "w3m";
	if (cset != nullptr) {
		argv[argc++] = "-I";
		argv[argc++] = "UTF-8";
	}
	argv[argc++] = "-O";
	argv[argc++] = "UTF-8";
	argv[argc++] = "-dump";
	argv[argc++] = filename.c_str();
	argv[argc]   = nullptr;
	auto pid = popenfd(argv, nullptr, &fout, nullptr, const_cast<const char *const *>(environ));
	if (pid < 0)
		return -1;
	int status = 0;
	auto cl3 = HX::make_scope_exit([&]() { waitpid(pid, &status, 0); });

	std::string outbuf;
	ssize_t ret;
	char fbuf[4096];
	while ((ret = ::read(fout, fbuf, std::size(fbuf))) > 0)
		outbuf.append(fbuf, ret);
	cl3.release();
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;
	final_buf = std::move(outbuf);
	return 0;
} catch (...) {
	return -1;
}

size_t gx_decompressed_size(const char *infile)
{
	wrapfd fd(::open(infile, O_RDONLY));
	if (fd.get() < 0)
		return errno == ENOENT ? SIZE_MAX : 0;
	struct stat sb;
	if (fstat(fd.get(), &sb) < 0 || !S_ISREG(sb.st_mode))
		return 0;
	size_t inbufsize = ZSTD_DStreamInSize();
	if (static_cast<unsigned long long>(sb.st_size) < inbufsize)
		inbufsize = sb.st_size;
	auto inbuf = std::make_unique<char[]>(inbufsize);
	auto rdret = ::read(fd.get(), inbuf.get(), inbufsize);
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
	wrapfd fd(::open(infile, O_RDONLY));
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
	auto cl_0 = HX::make_scope_exit([&]() { ZSTD_freeDStream(strm); });
	ZSTD_initDStream(strm);

	size_t inbufsize = ZSTD_DStreamInSize();
	if (static_cast<unsigned long long>(sb.st_size) < inbufsize)
		inbufsize = sb.st_size;
	auto inbuf = std::make_unique<char[]>(inbufsize);
#if defined(HAVE_POSIX_FADVISE)
	if (posix_fadvise(fd.get(), 0, sb.st_size, POSIX_FADV_SEQUENTIAL) != 0)
		/* ignore */;
#endif
	auto rdret = ::read(fd.get(), inbuf.get(), inbufsize);
	if (rdret < 0)
		return errno;
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
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ENOMEM;
}

errno_t gx_compress_tofd(std::string_view inbuf, int fd, uint8_t complvl)
{
#ifdef HAVE_FSETXATTR
	if (fsetxattr(fd, "btrfs.compression", "none", 4, XATTR_CREATE) != 0)
		/* ignore */;
#endif

	auto strm = ZSTD_createCStream();
	auto cl_0 = HX::make_scope_exit([&]() { ZSTD_freeCStream(strm); });
	ZSTD_initCStream(strm, complvl == 0 ? ZSTD_minCLevel() : complvl);
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
		if (HXio_fullwrite(fd, outds.dst, outds.pos) < 0)
			return EIO;
	}
	while (true) {
		outds.pos = 0;
		auto zr = ZSTD_compressStream2(strm, &outds, &inds, ZSTD_e_end);
		if (ZSTD_isError(zr))
			return EIO;
		if (HXio_fullwrite(fd, outds.dst, outds.pos) < 0)
			return EIO;
		if (zr == 0)
			break;
	}
	return 0;
}

errno_t gx_compress_tofile(std::string_view inbuf, const char *outfile,
    uint8_t complvl, unsigned int mode)
{
	wrapfd fd = ::open(outfile, O_WRONLY | O_TRUNC | O_CREAT, mode);
	auto ret = gx_compress_tofd(inbuf, fd.get(), complvl);
	if (ret != 0)
		return ret;
	return fd.close_wr();
}

std::string zstd_decompress(std::string_view x)
{
	std::string out;
	auto strm = ZSTD_createDStream();
	if (strm == nullptr)
		throw std::bad_alloc();
	auto cl_0 = HX::make_scope_exit([&]() { ZSTD_freeDStream(strm); });
	ZSTD_initDStream(strm);
	ZSTD_inBuffer xds = {x.data(), x.size()};
	auto ffsize = ZSTD_getFrameContentSize(x.data(), x.size());
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

/**
 * Given a file path, create all directories leading up to it.
 * @mode: desired mode of directory (+x is always auto-added)
 */
int gx_mkbasedir(const char *file, unsigned int mode)
{
	std::unique_ptr<char[], stdlib_delete> base(HX_dirname(file));
	if (base == nullptr)
		return -ENOMEM;
	if (mode & (S_IRUSR | S_IWUSR))
		mode |= S_IXUSR;
	if (mode & (S_IRGRP | S_IWGRP))
		mode |= S_IXGRP;
	if (mode & (S_IROTH | S_IWOTH))
		mode |= S_IXOTH;
	return HX_mkdir(base.get(), mode);
}

}

static errno_t read_file_by_line(FILE *fp, std::vector<std::string> &out)
{
	hxmc_t *line = nullptr;
	try {
		while (HX_getl(&line, fp) != nullptr) {
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

errno_t read_file_by_line(const char *file, std::vector<std::string> &out)
{
	std::unique_ptr<FILE, file_deleter> fp(fopen(file, "r"));
	if (fp == nullptr)
		return errno;
	return read_file_by_line(fp.get(), out);
}

errno_t read_file_by_line(const char *file, const char *sdlist, std::vector<std::string> &out)
{
	auto fp = fopen_sd(file, sdlist);
	if (fp == nullptr)
		return errno;
	return read_file_by_line(fp.get(), out);
}
