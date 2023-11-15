// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2021-2022 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <algorithm>
#include <cerrno>
#include <climits>
#include <clocale>
#include <cmath>
#include <csignal>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cwctype>
#include <fcntl.h>
#include <iconv.h>
#include <istream>
#include <list>
#include <memory>
#include <mutex>
#include <pthread.h>
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
#include <sys/resource.h>
#include <sys/socket.h>
#if defined(__linux__) && defined(__GLIBC__) && __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
#	include <sys/syscall.h>
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
#include <gromox/mapierr.hpp>
#include <gromox/paths.h>
#include <gromox/range_set.hpp>
#include <gromox/scope.hpp>
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
static std::mutex g_log_mutex;
static std::unique_ptr<FILE, file_deleter> g_logfp;
static bool g_log_tty, g_log_syslog;
static int gx_reexec_top_fd = -1;

static const char *mapi_errname(unsigned int e)
{
#define E(s) case (s): return #s;
	switch(e) {
	E(ecSuccess)
	E(ecUnknownUser)
	E(ecServerOOM)
	E(ecLoginPerm)
	E(ecNotSearchFolder)
	E(ecNoReceiveFolder)
	E(ecInvalidRecips)
	E(ecWrongServer)
	E(ecBufferTooSmall)
	E(ecSearchFolderScopeViolation)
	case ecRpcFormat: return "ecRpcFormat/ecNetwork";
	E(ecNullObject)
	E(ecQuotaExceeded)
	E(ecMaxAttachmentExceeded)
	E(ecSendAsDenied)
	E(ecNotExpanded)
	E(ecNotCollapsed)
	E(ecDstNullObject)
	E(ecMsgCycle)
	E(ecTooManyRecips)
	E(RPC_X_BAD_STUB_DATA)
	E(ecRejected)
	E(MAPI_W_NO_SERVICE)
	E(ecWarnWithErrors)
	E(MAPI_W_CANCEL_MESSAGE)
	E(SYNC_W_CLIENT_CHANGE_NEWER)
	E(ecInterfaceNotSupported)
	E(ecError)
	E(STG_E_ACCESSDENIED)
	E(StreamSeekError)
	E(STG_E_INVALIDPARAMETER)
	E(ecStreamSizeError)
	E(ecNotSupported)
	E(ecInvalidObject)
	E(ecObjectModified)
	E(ecObjectDeleted)
	E(ecInsufficientResrc)
	E(ecNotFound)
	E(ecLoginFailure)
	E(ecUnableToAbort)
	E(ecRpcFailed)
	E(ecTooComplex)
	E(ecComputed)
	E(MAPI_E_UNKNOWN_CPID)
	E(MAPI_E_UNKNOWN_LCID)
	E(ecTooBig)
	E(MAPI_E_DECLINE_COPY)
	E(ecTableTooBig)
	E(ecInvalidBookmark)
	E(ecNotInQueue)
	E(ecDuplicateName)
	E(ecNotInitialized)
	E(MAPI_E_NO_RECIPIENTS)
	E(ecRootFolder)
	E(MAPI_E_STORE_FULL)
	E(EC_EXCEEDED_SIZE)
	E(ecAmbiguousRecip)
	E(SYNC_E_OBJECT_DELETED)
	E(SYNC_E_IGNORE)
	E(SYNC_E_CONFLICT)
	E(SYNC_E_NO_PARENT)
	E(ecNPQuotaExceeded)
	E(NotImplemented)
	E(ecAccessDenied)
	E(ecMAPIOOM)
	E(ecInvalidParam)
	E(MAPI_E_ACCOUNT_DISABLED)
	E(MAPI_E_END_OF_SESSION)
	E(MAPI_E_FAILONEPROVIDER)
	E(MAPI_E_INVALID_WORKSTATION_ACCOUNT)
	E(MAPI_E_PASSWORD_CHANGE_REQUIRED)
	E(MAPI_E_PASSWORD_EXPIRED)
	E(MAPI_E_UNCONFIGURED)
	E(MAPI_E_UNKNOWN_ENTRYID)
	E(ecCorruptData)
	E(ecInvalidEntryId)
	E(ecTableEmpty)
	E(ecTimeSkew)
	default: {
		thread_local char xbuf[32];
		snprintf(xbuf, std::size(xbuf), "%xh", e);
		return xbuf;
	}
	}
#undef E
}

const char *mapi_errname_r(unsigned int e, char *b, size_t bz)
{
	HX_strlcpy(b, mapi_errname(e), bz);
	return b;
}

const char *mapi_strerror(unsigned int e)
{
	// STG = storage
#define E(v, s) case v: return s;
	switch (e) {
	E(ecSuccess, "The operation succeeded")
	E(ecUnknownUser, "User is unknown to the system")
	E(ecServerOOM, "Server could not allocate memory")
	E(ecLoginPerm, "This user does not have access rights to the mailbox")
	E(ecNotSearchFolder, "The operation is valid only on a search folder")
	E(ecNoReceiveFolder, "No receive folder is available")
	E(ecInvalidRecips, "No valid recipients set on the message")
	E(ecWrongServer, "The server does not host the user's mailbox database")
	E(ecBufferTooSmall, "A buffer passed to this function is not big enough")
	E(ecSearchFolderScopeViolation, "Attempted to perform a recursive search on a search folder")
	E(ecRpcFormat, "A badly formatted RPC buffer was detected")
	E(ecNullObject, "An object handle reference in the RPC buffer could not be resolved")
	E(ecQuotaExceeded, "The operation failed because it would have exceeded a resource quota")
	E(ecMaxAttachmentExceeded, "The maximum number of message attachments has been exceeded")
	E(ecNotExpanded, "Error in expanding or collapsing rows in a categorized view")
	E(ecNotCollapsed, "Error in expanding or collapsing rows in a categorized view")
	E(ecDstNullObject, "The RPC buffer contains a destination object handle that could not be resolved to a Server object.")
	E(ecMsgCycle, "The source message contains the destination message and cannot be attached to it")
	E(ecTooManyRecips, "A hard limit on the number of recipients per message was exceeded")
	E(RPC_X_BAD_STUB_DATA, "RPC_X_BAD_STUB_DATA")
	E(ecRejected, "The operation was rejected")
	E(ecWarnWithErrors, "A request involving multiple properties failed for one or more individual properties, while succeeding overall")
	E(SYNC_W_CLIENT_CHANGE_NEWER, "In a change conflict, the client has the more recent change.")
	E(ecError, "The operation failed for an unspecified reason")
	E(STG_E_ACCESSDENIED, "Insufficient access rights to perform the operation")
	E(STG_E_INVALIDPARAMETER, "Invalid parameter passed to a IStorage/IStream operation")
	E(ecStreamSizeError, "The maximum size for the object was reached")
	E(StreamSeekError, "Tried to seek to offset before the start or beyond the max stream size of 2^31")
	E(ecNotSupported, "The server does not support this method call")
	E(ecInvalidObject, "A method call was made using a reference to an object that has been destroyed or is not in a viable state")
	E(ecObjectModified, "Change commit failed because the object was changed separately")
	E(ecObjectDeleted, "Change commit suppressed because the object was deleted on the server")
	E(ecInsufficientResrc, "Not enough of an unspecified resource was available to complete the operation")
	E(ecNotFound, "The requested object could not be found at the server")
	E(ecLoginFailure, "Client unable to log on to the server")
	E(ecUnableToAbort, "The operation cannot be aborted")
	E(ecRpcFailed, "An operation was unsuccessful because of a problem with network operations or services./The RPC was rejected for an unspecified reason.")
	E(ecTooComplex, "The operation requested is too complex for the server to handle")
	E(MAPI_E_UNKNOWN_CPID, "Unknown codepage ID")
	E(MAPI_E_UNKNOWN_LCID, "Unknown locale ID")
	E(ecTooBig, "The result set of the operation is too big for the server to return")
	E(MAPI_E_DECLINE_COPY, "The server cannot copy the object, possibly due to cross-server copy")
	E(ecTableTooBig, "The table is too big for the requested operation to complete")
	E(ecInvalidBookmark, "The bookmark passed to a table operation was not created on the same table")
	E(ecNotInQueue, "The message is no longer in the spooler queue of the message store")
	E(ecDuplicateName, "A folder or item cannot be created because one with the same name or other criteria already exists.")
	E(ecNotInitialized, "The subsystem is not ready")
	E(ecRootFolder, "A folder move or copy operation would create a cycle")
	E(EC_EXCEEDED_SIZE, "The message size exceeds the configured size limit")
	E(ecAmbiguousRecip, "An unresolved recipient matches more than one directory entry")
	E(SYNC_E_IGNORE, "A sync error occurred, but can be ignored, e.g. superseded change")
	E(SYNC_E_CONFLICT, "Conflicting changes to an object have been detected")
	E(SYNC_E_NO_PARENT, "The parent folder could not be found")
	E(NotImplemented, "Function is not implemented")
	E(ecAccessDenied, "Insufficient access rights to perform the operation")
	E(ecMAPIOOM, "Not enough memory was available to complete the operation")
	E(ecInvalidParam, "An invalid parameter was passed to a function or remote procedure call")
	E(ecInterfaceNotSupported, "MAPI interface not supported")
	E(ecInvalidEntryId, "Invalid EntryID")
	E(ecCorruptData, "There is an internal inconsistency in a database, or in a complex property value")
	E(MAPI_E_UNCONFIGURED, "One or more of the configuration properties were unavailable")
	E(MAPI_E_FAILONEPROVIDER, "MAPI Provider could not be configured")
	E(MAPI_E_PASSWORD_CHANGE_REQUIRED, "Password change is required")
	E(MAPI_E_PASSWORD_EXPIRED, "Password has expired")
	E(MAPI_E_INVALID_WORKSTATION_ACCOUNT, "Invalid workstation account")
	E(ecTimeSkew, "The operation failed due to clock skew between servers")
	E(MAPI_E_ACCOUNT_DISABLED, "Account is disabled")
	E(MAPI_E_END_OF_SESSION, "The server session has been destroyed, possibly by a server restart")
	E(MAPI_E_UNKNOWN_ENTRYID, "The EntryID passed to OpenEntry was created by a different MAPI provider")
	E(ecTableEmpty, "A table essential to the operation is empty")
	E(MAPI_E_NO_RECIPIENTS, "A message cannot be sent because it has no recipients")
	E(MAPI_E_STORE_FULL, "Store is full")
	E(MAPI_W_CANCEL_MESSAGE, "Message was cancelled (e.g. incomplete Envelope-From/Ev-To)")
	E(MAPI_W_NO_SERVICE, "The desired service is unavailable")
	E(SYNC_E_OBJECT_DELETED, "The object no longer exists on the server")
	E(ecComputed, "The property is a computed property and read-only")
	E(ecNPQuotaExceeded, "The maximum number of named properties was reached in the store")
	E(ecSendAsDenied, "Not enough permissions to utilize Send-As impersonation")
	default: {
		thread_local char xbuf[40];
		snprintf(xbuf, sizeof(xbuf), "Unknown MAPI error code %xh", e);
		return xbuf;
	}
	}
#undef E
}

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

/**
 * This function gives an approximation only, and it is only used for debug
 * prints because of that. apptimes are timezoneless, so the conversion to
 * nttime is necessarily off by as much as timezone you are on.
 */
uint64_t apptime_to_nttime_approx(double v)
{
	uint64_t s = std::modf(v, &v) * 86400;
	uint64_t d = v;
	s += 9435312000;
	if (d < 61)
		s += 86400;
	s += d * 86400;
	s *= 10000000;
	return s;
}

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
	while ((ret = read(fout, fbuf, std::size(fbuf))) > 0)
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

/**
 * Use of octal representation: it is shortest (\377 is just as long as \xff,
 * but \0 is shorter than \x00).
 *
 * Average expansion: x2.35
 * Worst expansion: x4.00
 */
std::string bin2cstr(const void *vdata, size_t len)
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

/**
 * Represent a binary blob in a form that is somewhat compact but also show
 * ASCII and low control codes recognizably.
 *
 * Average expansion: x2.13
 * Worst expansion: x3.00
 */
std::string bin2txt(const void *vdata, size_t len)
{
	auto data = static_cast<const unsigned char *>(vdata);
	std::string ret;
	char b[4]{};
	for (size_t i = 0; i < len; ++i) {
		if (data[i] < 32) {
			static constexpr char enc[] = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_";
			b[0] = '^';
			b[1] = enc[data[i]];
			b[2] = '\0';
		} else if (isprint(data[i]) && data[i] != '"' &&
		    data[i] != '\'' && data[i] != '\\' && data[i] != '^') {
			b[0] = data[i];
			b[1] = '\0';
		} else {
			static constexpr char enc[] = "0123456789abcdef";
			b[0] = '^';
			b[1] = enc[data[i] >> 4];
			b[2] = enc[data[i] & 0xf];
		}
		ret.append(b);
	}
	return ret;
}

/**
 * Average expansion: x2.00
 * Worst expansion: x2.00
 */
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

void rfc1123_dstring(char *buf, size_t z, const struct tm &tm)
{
	strftime(buf, z, "%a, %d %b %Y %T GMT", &tm);
}

void rfc1123_dstring(char *buf, size_t z, time_t ts)
{
	if (ts == 0)
		ts = time(nullptr);
	struct tm tm;
	gmtime_r(&ts, &tm);
	return rfc1123_dstring(buf, z, tm);
}

void startup_banner(const char *prog)
{
	fprintf(stderr, "\n");
	mlog(LV_NOTICE, "%s %s (pid %ld uid %ld)", prog, PACKAGE_VERSION,
	        static_cast<long>(getpid()), static_cast<long>(getuid()));
	fprintf(stderr, "\n");
}

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
		auto ret = gx_reexec(argv);
		if (ret != 0)
			return ret;
		auto m = umask(07777);
		m = (m & ~0070) | ((m & 0700) >> 3);
		umask(m);
		return 0;
	}
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

ec_error_t cu_validate_msgclass(const char *k)
{
	/* MS-OXCSTOR v25 §2.2.1.2ff */
	auto z = strlen(k);
	if (z + 1 > 255 || k[0] == '.' || (z > 0 && k[z-1] == '.'))
		return ecInvalidParam;
	for (size_t i = 0; i < z; ++i) {
		if (k[i] < 0x20 || k[i] > 0x7E)
			return ecInvalidParam;
		if (k[i] == '.' && k[i+1] == '.')
			return ecInvalidParam;
	}
	return ecSuccess;
}

bool cpid_cstr_compatible(cpid_t cpid)
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

static void init_locale()
{
	setlocale(LC_ALL, "C.UTF-8");
	if (iswalnum(0x79C1))
		return;
	setlocale(LC_ALL, "en_US.UTF-8");
}

int iconv_validate()
{
	init_locale();
	for (const auto s : {"UTF-16LE", "windows-1252",
	     "iso-8859-1", "iso-2022-jp"}) {
		auto k = iconv_open("UTF-8", s);
		if (k == (iconv_t)-1) {
			mlog(LV_ERR, "I can't work like this! iconv lacks support for the essential character set %s. "
			        "Perhaps you need to install some libc locale package.", s);
			return -errno;
		}
		iconv_close(k);
	}
	return 0;
}

bool get_digest(const Json::Value &jval, const char *key, char *out, size_t outmax) try
{
	if (jval.type() != Json::ValueType::objectValue || !jval.isMember(key))
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

bool get_digest(const char *json, const char *key, char *out, size_t outmax) try
{
	Json::Value jval;
	if (!gromox::json_from_str(json, jval))
		return false;
	return get_digest(jval, key, out, outmax);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1324: ENOMEM");
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

void tmpfile::close()
{
	if (m_fd < 0)
		return;
	::close(m_fd);
	m_fd = -1;
	if (m_path.empty())
		return;
	if (remove(m_path.c_str()) < 0 && errno != ENOENT)
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
		m_fd = open(dir, O_TMPFILE | flags, mode);
		if (m_fd >= 0)
			return m_fd;
		if (errno != EISDIR && errno != EOPNOTSUPP)
			return -errno;
	}
#endif
	char tn[17];
	randstring(tn, 16, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
	m_path = dir + "/"s + tn;
	m_fd = open(m_path.c_str(), O_CREAT | flags, mode);
	return m_fd >= 0 ? m_fd : -errno;
} catch (const std::bad_alloc &) {
	return -ENOMEM;
}

errno_t tmpfile::link_to(const char *newpath)
{
	if (m_path.empty())
		return EINVAL;
	if (m_fd < 0)
		return EBADF;
	/*
	 * The use of renameat2(RENAME_NOREPLACE) to speed up the CID writer in
	 * one particular edge case was evaluated, but it is not worth it.
	 */
	if (rename(m_path.c_str(), newpath) != 0)
		return errno;
	m_path.clear();
	return 0;
}

void mlog_init(const char *filename, unsigned int max_level)
{
	g_max_loglevel = max_level;
	if (filename == nullptr || *filename == '\0' || strcmp(filename, "-") == 0)
		g_logfp.reset();
	g_log_syslog = filename != nullptr && strcmp(filename, "syslog") == 0;
	g_log_tty    = isatty(STDERR_FILENO);
	if (g_logfp == nullptr && getppid() == 1 && getenv("JOURNAL_STREAM") != nullptr)
		g_log_syslog = true;
	if (g_log_syslog) {
		openlog(nullptr, LOG_PID, LOG_MAIL);
		setlogmask((1 << (max_level + 2)) - 1);
		return;
	}
	if (g_logfp == nullptr) {
		setvbuf(stderr, nullptr, _IOLBF, 0);
		return;
	}
	std::lock_guard hold(g_log_mutex);
	g_logfp.reset(fopen(filename, "a"));
	if (g_logfp == nullptr) {
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
	} else if (g_logfp == nullptr) {
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
	{
		std::lock_guard hold(g_log_mutex);
		fputs(buf, g_logfp.get());
		vfprintf(g_logfp.get(), fmt, args);
		fputc('\n', g_logfp.get());
	}
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
	return (errno = ret);
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

errno_t gx_compress_tofd(std::string_view inbuf, int fd, uint8_t complvl)
{
#ifdef HAVE_FSETXATTR
	if (fsetxattr(fd, "btrfs.compression", "none", 4, XATTR_CREATE) != 0)
		/* ignore */;
#endif

	auto strm = ZSTD_createCStream();
	auto cl_0 = make_scope_exit([&]() { ZSTD_freeCStream(strm); });
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
	wrapfd fd = open(outfile, O_WRONLY | O_TRUNC | O_CREAT, mode);
	auto ret = gx_compress_tofd(inbuf, fd.get(), complvl);
	if (ret != 0)
		return ret;
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

std::string json_to_str(const Json::Value &jv)
{
	Json::StreamWriterBuilder swb;
	swb["indentation"] = "";
	return Json::writeString(swb, jv);
}

errno_t parse_imap_seq(imap_seq_list &r, const char *s) try
{
	char *end = nullptr;
	r.clear();
	for (; *s != '\0'; s = &end[1]) {
		if (*s == ',') {
			end = const_cast<char *>(s);
			continue;
		}
		auto min = *s == '*' ? ULONG_MAX : strtoul(s, &end, 0);
		if (*s == '*')
			end = const_cast<char *>(&s[1]);
		if (*end == '\0') {
			r.insert(min, min);
			break;
		} else if (*end == ',') {
			r.insert(min, min);
			continue;
		} else if (*end != ':') {
			return EINVAL;
		}
		s = &end[1];
		auto max = *s == '*' ? ULONG_MAX : strtoul(s, &end, 0);
		if (*s == '*')
			end = const_cast<char *>(&s[1]);
		if (max < min)
			std::swap(min, max);
		if (*end == '\0') {
			r.insert(min, max);
			break;
		} else if (*end != ',') {
			return EINVAL;
		}
		r.insert(min, max);
	}
	return 0;
} catch (const std::bad_alloc &) {
	return ENOMEM;
}

/*
 * On match, 0 is returned; otherwise anything non-zero.
 */
int strtailcase(const char *h, const char *n)
{
	size_t hz = strlen(h), nz = strlen(n);
	if (hz < nz)
		return -1;
	return strcasecmp(&h[hz-nz], n);
}

size_t utf8_printable_prefix(const void *vinput, size_t max)
{
	auto begin = static_cast<const uint8_t *>(vinput);
	if (begin == nullptr)
		return 0;
	const uint8_t *p = begin;
	for (uint8_t seg = 0; max > 0 && *p != '\0'; ++p, --seg, --max) {
		if (seg == 0) {
			if (iscntrl(*p) && !isspace(*p))
				break;
			seg = utf8_byte_num[*p];
			if (seg == 0)
				break;
		} else if ((*p & 0xc0) != 0x80) {
			break;
		}
	}
	return p - begin;
}

errno_t filedes_limit_bump(unsigned int max)
{
	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
		mlog(LV_ERR, "getrlimit: %s", strerror(errno));
		return EXIT_FAILURE;
	}
	if (rl.rlim_cur < max) {
		rl.rlim_cur = max;
		rl.rlim_max = max;
		if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
			mlog(LV_WARN, "setrlimit RLIMIT_NFILE %lu: %s",
				static_cast<unsigned long>(rl.rlim_max), strerror(errno));
			return errno;
		}
	}
	mlog(LV_NOTICE, "system: maximum file descriptors: %lu",
		static_cast<unsigned long>(rl.rlim_cur));
	return 0;
}

std::string iconvtext(const char *src, size_t src_size,
    const char *from, const char *to)
{
	if (strcasecmp(from, to) == 0)
		return {reinterpret_cast<const char *>(src), src_size};
	auto cs = to + "//IGNORE"s;
	auto cd = iconv_open(cs.c_str(), from);
	if (cd == reinterpret_cast<iconv_t>(-1)) {
		mlog(LV_ERR, "E-2116: iconv_open %s: %s",
		        cs.c_str(), strerror(errno));
		return "UNKNOWN_CHARSET";
	}
	auto cleanup = make_scope_exit([&]() { iconv_close(cd); });
	char buffer[4096];
	std::string out;

	while (src_size > 0) {
		auto dst = buffer;
		size_t dst_size = sizeof(buffer);
		auto ret = iconv(cd, (char**)&src, &src_size, (char**)&dst, &dst_size);
		if (ret != static_cast<size_t>(-1) || dst_size != sizeof(buffer)) {
			out.append(buffer, sizeof(buffer) - dst_size);
			continue;
		}
		if (src_size > 0) {
			--src_size;
			++src;
		}
		out.append(buffer, sizeof(buffer) - dst_size);
	}
	return out;
}

unsigned long gx_gettid()
{
#if defined(__linux__) && defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 30))
	return gettid();
#elif defined(__linux__)
	return syscall(SYS_gettid);
#elif defined(__OpenBSD__)
	return getthrid();
#else
	return (unsigned long)pthread_self();
#endif
}

std::string base64_encode(const std::string_view &x)
{
	std::string out;
	out.resize((x.size() + 3) / 3 * 4);
	size_t final_size = 0;
	int ret = encode64(x.data(), x.size(), out.data(), out.size() + 1, &final_size);
	if (ret < 0)
		out.clear();
	else
		out.resize(final_size);
	return out;
}

std::string base64_decode(const std::string_view &x)
{
	std::string out;
	out.resize(x.size());
	size_t final_size = 0;
	int ret = decode64_ex(x.data(), x.size(), out.data(), x.size(), &final_size);
	if (ret < 0)
		out.clear();
	else
		out.resize(final_size);
	return out;
}

}

int XARRAY::append(MITEM &&ptr, unsigned int tag) try
{
	if (tag == 0 || get_itemx(tag) != nullptr)
		return -1;
	m_hash.emplace(tag, m_vec.size());
	try {
		m_vec.push_back(std::move(ptr));
	} catch (const std::bad_alloc &) {
		m_hash.erase(tag);
		return -1;
	}
	return 0;
} catch (const std::bad_alloc &) {
	return -1;
}

void XARRAY::clear()
{
	m_vec.clear();
	m_hash.clear();
}

config_file::cfg_entry::cfg_entry(const cfg_directive &d) :
	m_min(znul(d.min)), m_max(znul(d.max)), m_flags(d.flags)
{
	set(d.deflt);
}

void config_file::cfg_entry::set(const char *sv)
{
	if (m_flags & CFG_BOOL) {
		m_val = parse_bool(sv) ? "1" : "0";
	} else if (m_flags & CFG_TIME) {
		auto nv = HX_strtoull_sec(sv, nullptr);
		if (m_min.size() > 0)
			nv = std::max(nv, HX_strtoull_sec(m_min.c_str(), nullptr));
		if (m_max.size() > 0)
			nv = std::min(nv, HX_strtoull_sec(m_max.c_str(), nullptr));
		m_val = std::to_string(nv);
	} else if (m_flags & CFG_SIZE) {
		auto nv = HX_strtoull_unit(sv, nullptr, 1024);
		if (m_min.size() > 0)
			nv = std::max(nv, HX_strtoull_unit(m_min.c_str(), nullptr, 1024));
		if (m_max.size() > 0)
			nv = std::min(nv, HX_strtoull_unit(m_max.c_str(), nullptr, 1024));
		m_val = std::to_string(nv);
	} else {
		m_val = sv;
	}
}

config_file::config_file(const cfg_directive *kd)
{
	if (kd != nullptr)
		for (; kd->key != nullptr; ++kd)
			m_vars.emplace(kd->key, cfg_entry{*kd});
}

const char *config_file::get_value(const char *sk) const
{
	std::string key = sk;
	while (true) {
		HX_strlower(key.data());
		auto i = m_vars.find(key);
		if (i == m_vars.cend())
			return nullptr;
		if (i->second.m_flags & CFG_ALIAS) {
			key = i->second.m_val.c_str();
			continue;
		}
		return i->second.m_val.c_str();
	}
}

/**
 * Not suitable for signed or maybe-signed (e.g. time_t) quantities.
 */
unsigned long long config_file::get_ll(const char *key) const
{
	auto s = get_value(key);
	if (s == nullptr) {
		mlog(LV_ERR, "*** config key \"%s\" has no default and was not set either; yielding 0", key);
		return 0;
	}
	return strtoull(s, nullptr, 0);
}

void config_file::set_value(const char *sk, const char *sv) try
{
	std::string key = sk;
	while (true) {
		HX_strlower(key.data());
		auto i = m_vars.find(key);
		if (i == m_vars.end()) {
//			printf("\e[32m\t%s = \e[1m%s\e[0m\n", key, sv);
			m_vars.emplace(key, cfg_entry{sv});
			return;
		} else if (i->second.m_flags & CFG_ALIAS) {
//			printf("\e[32m\t%s ...\e[0m\n", key, sv);
			key = i->second.m_val.c_str();
		} else {
//			printf("\e[32m\t%s = \e[1m%s\e[0m\n", key, sv);
			i->second.set(sv);
			return;
		}
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2367: ENOMEM");
}

BOOL config_file::save()
{
	if (std::none_of(m_vars.cbegin(), m_vars.cend(),
	    [&](const value_type &kv) { return kv.second.m_flags & CFG_TOUCHED; }))
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

std::shared_ptr<CONFIG_FILE> config_file_init(const char *filename,
    const cfg_directive *key_desc) try
{
	auto cfg = std::make_shared<CONFIG_FILE>(key_desc);
	cfg->m_filename = filename;
	std::unique_ptr<FILE, file_deleter> fh(fopen(filename, "r"));
	if (fh == nullptr)
		return nullptr;
	hxmc_t *line = nullptr;
	auto cl_0 = make_scope_exit([&]() { HXmc_free(line); });
	while (HX_getl(&line, fh.get()) != nullptr) {
		HX_chomp(line);
		HX_strrtrim(line);
		auto p = line;
		while (HX_isspace(*p))
			++p;
		if (*line == '#')
			continue;
		auto key_begin = p;
		while (*p != '\0' && *p != '=' && !HX_isspace(*p))
			++p;
		auto key_end = p;
		while (HX_isspace(*p))
			++p;
		if (*p != '=')
			continue;
		++p;
		while (HX_isspace(*p))
			++p;
		*key_end = '\0';
		cfg->set_value(key_begin, p);
	}
	return cfg;
} catch (const std::bad_alloc &) {
	return nullptr;
}

/**
 * @fb:		filename (base) - "foo.cfg"
 * @sdlist:	colon-separated path list
 *
 * Attempt to read config file @fb from various paths (@sdlist).
 */
std::shared_ptr<CONFIG_FILE> config_file_initd(const char *fb,
    const char *sdlist, const cfg_directive *key_desc) try
{
	if (sdlist == nullptr || strchr(fb, '/') != nullptr)
		return config_file_init(fb, key_desc);
	errno = 0;
	for (auto &&dir : gx_split(sdlist, ':')) {
		if (dir.size() == 0)
			continue;
		errno = 0;
		auto full = std::move(dir) + "/" + fb;
		auto cfg = config_file_init(full.c_str(), key_desc);
		if (cfg != nullptr)
			return cfg;
		if (errno != ENOENT) {
			mlog(LV_ERR, "config_file_initd %s: %s",
			        full.c_str(), strerror(errno));
			return nullptr;
		}
	}
	return std::make_shared<CONFIG_FILE>(key_desc);
} catch (const std::bad_alloc &) {
	errno = ENOMEM;
	return nullptr;
}

static const char *default_searchpath()
{
	const char *ed = getenv("GROMOX_CONFIG_PATH");
	return ed != nullptr ? ed : PKGSYSCONFDIR;
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
		return config_file_initd(fb, default_searchpath(), key_desc);
	auto cfg = config_file_init(ov, key_desc);
	if (cfg == nullptr)
		mlog(LV_ERR, "config_file_init %s: %s", ov, strerror(errno));
	return cfg;
}
