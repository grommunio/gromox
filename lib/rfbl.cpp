// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021-2024 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <climits>
#include <clocale>
#include <cmath>
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
#include <memory>
#include <mutex>
#include <netdb.h>
#include <pwd.h>
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
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#if defined(HAVE_SYS_XATTR_H)
#	include <sys/xattr.h>
#endif
#include <json/reader.h>
#include <json/writer.h>
#include <libHX/ctype_helper.h>
#include <libHX/defs.h>
#include <libHX/io.h>
#include <libHX/proc.h>
#include <libHX/string.h>
#include <vmime/charset.hpp>
#include <gromox/archive.hpp>
#include <gromox/atomic.hpp>
#include <gromox/clock.hpp>
#include <gromox/config_file.hpp>
#include <gromox/endian.hpp>
#include <gromox/fileio.h>
#include <gromox/generic_connection.hpp>
#include <gromox/json.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapierr.hpp>
#include <gromox/paths.h>
#include <gromox/process.hpp>
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
	E(ecZNullObject)
	E(ecZOutOfHandles)
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
	E(ecZNullObject, "Bad input handle")
	E(ecZOutOfHandles, "Too many object handles open")
	default: {
		thread_local char xbuf[40];
		snprintf(xbuf, sizeof(xbuf), "Unknown MAPI error code %xh", e);
		return xbuf;
	}
	}
#undef E
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

int feed_w3m(const void *inbuf, size_t len, std::string &outbuf) try
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
	if (!WIFEXITED(status))
		return -1;
	if (outbuf.empty())
		return 0;
	/* The caller can just look at outbuf.size() */
	return 1;
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
 * Average expansion: x2.71
 * Worst expansion: x4.00
 */
std::string bin2cstr(const void *vdata, size_t len)
{
	auto data = static_cast<const unsigned char *>(vdata);
	std::string ret;
	char b[5];
	for (size_t i = 0; i < len; ++i) {
		b[0] = '\\';
		b[2] = '\0';
		switch (data[i]) {
		case '\a': b[1] = 'a'; break;
		case '\b': b[1] = 'b'; break;
		case '\f': b[1] = 'f'; break;
		case '\n': b[1] = 'n'; break;
		case '\r': b[1] = 'r'; break;
		case '\t': b[1] = 't'; break;
		case '\v': b[1] = 'v'; break;
		case '"':
		case '\\':
			b[1] = data[i]; break;
		default: {
			if (isprint(data[i])) {
				b[0] = data[i];
				b[1] = '\0';
				break;
			}
			char next_char = i < len && i + 1 < len ? data[i+1] : 0;
			auto next_unsafe = next_char >= '0' && next_char <= '7';
			if (next_unsafe || data[i] >= 0100) {
				b[1] = '0' + (data[i] / 64 % 8);
				b[2] = '0' + (data[i] / 8 % 8);
				b[3] = '0' + (data[i] % 8);
				b[4] = '\0';
			} else if (data[i] >= 0010) {
				b[1] = '0' + (data[i] / 8 % 8);
				b[2] = '0' + (data[i] % 8);
				b[3] = '\0';
			} else {
				b[1] = '0' + (data[i] % 8);
			}
			break;
		}
		}
		ret.append(b);
	}
	return ret;
}

/**
 * Represent a binary blob in a form that is somewhat compact but also show
 * ASCII and low control codes recognizably.
 *
 * Average expansion: x2.15
 * Worst expansion: x3.00
 */
namespace {
struct bin2txt_init {
	bin2txt_init() { m_cstr = *znul(getenv("BIN2TXT_CSTR")) != '\0'; }
	bool m_cstr = false;
};
static bin2txt_init g_bin2txt_choice;
}

std::string bin2txt(const void *vdata, size_t len)
{
	if (g_bin2txt_choice.m_cstr)
		return bin2cstr(vdata, len);
	auto data = static_cast<const unsigned char *>(vdata);
	std::string ret;
	char b[4]{};
	for (size_t i = 0; i < len; ++i) {
		if (data[i] == '\n') {
			b[0] = '\\';
			b[1] = 'n';
			b[2] = '\0';
		} else if (data[i] == '\r') {
			b[0] = '\\';
			b[1] = 'r';
			b[2] = '\0';
		} else if (data[i] < 32) {
			static constexpr char enc[] = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_";
			b[0] = '^';
			b[1] = enc[data[i]];
			b[2] = '\0';
		} else if (data[i] == '"' || data[i] == '\\') {
			b[0] = '\\';
			b[1] = data[i];
			b[2] = '\0';
		} else if (isprint(data[i]) && data[i] != '^') {
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
	if (gmtime_r(&ts, &tm) != nullptr)
		rfc1123_dstring(buf, z, tm);
	else
		*buf = '\0';
}

void startup_banner(const char *prog)
{
	fprintf(stderr, "\n");
	mlog(LV_NOTICE, "%s %s (pid %ld uid %ld)", prog, PACKAGE_VERSION,
	        static_cast<long>(getpid()), static_cast<long>(getuid()));
	fprintf(stderr, "\n");
}

errno_t switch_user_exec(const CONFIG_FILE &cf, char *const *argv)
{
	return switch_user_exec(cf.get_value("running_identity"), argv);
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
	 * write()+rename() could succeed and only close() could return ENOSPC.
	 * This breaks the tmpfile class's goal for atomic placement of
	 * files-with-content. Call fsync as a remedy.
	 */
	if (fsync(m_fd) < 0)
		return errno;
	/*
	 * The use of renameat2(RENAME_NOREPLACE) to speed up the CID writer in
	 * one particular edge case was evaluated, but it is not worth it.
	 */
	if (rename(m_path.c_str(), newpath) != 0)
		return errno;
	m_path.clear();
	return 0;
}

void mlog_init(const char *ident, const char *filename, unsigned int max_level,
    const char *user)
{
	g_max_loglevel = max_level;
	bool for_syslog = false, for_tty = false;
	if (filename == nullptr || *filename == '\0') {
		if (isatty(STDERR_FILENO))
			for_tty = true;
		else if (getppid() == 1 && getenv("JOURNAL_STREAM") != nullptr)
			for_syslog = true;
	} else if (strcmp(filename, "syslog") == 0) {
		for_syslog = true;
	} else if (strcmp(filename, "-") == 0) {
		for_tty = true;
	}
	if (for_syslog) {
		openlog(ident, LOG_PID, LOG_MAIL);
		setlogmask((1 << (max_level + 2)) - 1);
		g_log_syslog = true;
		g_log_tty = false;
		g_logfp.reset();
		return;
	}
	if (for_tty) {
		g_log_tty = true;
		g_log_syslog = false;
		g_logfp.reset();
		setvbuf(stderr, nullptr, _IOLBF, 0);
		return;
	}
	g_log_tty = g_log_syslog = false;
	if (user != nullptr) {
		auto fd = open(filename, O_RDWR | O_CREAT | O_EXCL, FMODE_PRIVATE);
		if (fd >= 0) {
			char buf[256];
			struct passwd pwd{}, *result = nullptr;
			if (getpwnam_r(user, &pwd, buf, std::size(buf), &result) == 0 &&
			    result != nullptr)
				fchown(fd, result->pw_uid, result->pw_gid);
			close(fd);
		}
	}
	std::lock_guard hold(g_log_mutex);
	g_logfp.reset(fopen(filename, "a"));
	if (g_logfp == nullptr) {
		g_log_tty = true;
		g_log_syslog = false;
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
		if (g_log_tty) {
			auto c = level <= LV_ERR ? "\e[1;31m" :
				 level <= LV_WARN ? "\e[31m" :
				 level <= LV_NOTICE ? "\e[1;37m" :
				 level == LV_DEBUG ? "\e[1;30m" : "";
			if (*c != '\0')
				fputs(c, stderr);
		}
#if 0
		fprintf(stderr, "[%f] ", std::chrono::duration<double>(tp_now() - decltype(tp_now()){}).count());
#endif
		vfprintf(stderr, fmt, args);
		if (g_log_tty)
			fputs("\e[0m\n", stderr);
		else
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

int ssllog(const char *str, size_t len, void *lvp)
{
	auto level = reinterpret_cast<uintptr_t>(lvp);
	mlog(level, "%.*s", static_cast<int>(std::min(static_cast<size_t>(INT_MAX), len)), str);
	return 1;
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
#if defined(HAVE_POSIX_FADVISE)
	if (posix_fadvise(fd.get(), 0, sb.st_size, POSIX_FADV_SEQUENTIAL) != 0)
		/* ignore */;
#endif
	auto rdret = read(fd.get(), inbuf.get(), inbufsize);
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

namespace {

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

}

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

/**
 * @h: class on message
 * @n: class to test
 *
 * On match, 0 is returned; otherwise whatever strcasecmp would yield.
 */
int class_match_prefix(const char *h, const char *n)
{
	if (h == nullptr)
		return -1;
	size_t z = strlen(n);
	auto ret = strncasecmp(h, n, z);
	if (ret != 0)
		return ret;
	return h[z] == '\0' || h[z] == '.' ? 0 : 1;
}

/**
 * On match, 0 is returned; otherwise anything non-zero.
 */
int class_match_suffix(const char *h, const char *n)
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

static std::string dom2idna(const std::string_view dom)
{
	std::string idn, part;
	size_t p = 0;

	for (size_t n; (n = dom.find('.', p)) != dom.npos; p = n + 1) {
		part.clear();
		vmime::charset::convert(std::string(&dom[p], &dom[n]), part,
			vmime::charsets::UTF_8, vmime::charsets::IDNA);
		idn += std::move(part) + '.';
	}
	if (p >= dom.length())
		return idn;
	part.clear();
	vmime::charset::convert(std::string(dom.begin() + p, dom.end()), part,
		vmime::charsets::UTF_8, vmime::charsets::IDNA);
	idn += std::move(part);
	return idn;
}

std::string gx_utf8_to_punycode(const char *addr)
{
	auto at = strchr(addr, '@');
	if (at == nullptr)
		return addr;
	++at;
	return std::string(addr, at - addr) + dom2idna(at);
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
		auto entryofs = le32p_to_cpu(&mapped_area[deofs+56]);
		auto entrysz  = le32p_to_cpu(&mapped_area[deofs+60]);
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

bool str_isascii(const char *s)
{
	for (; *s != '\0'; ++s)
		if (!isascii(static_cast<unsigned char>(*s)))
			return false;
	return true;
}

bool str_isasciipr(const char *s)
{
	for (; *s != '\0'; ++s) {
		unsigned char c = *s;
		if (!isascii(c) && !isprint(c))
			return false;
	}
	return true;
}

int haproxy_intervene(int fd, unsigned int level, struct sockaddr_storage *ss)
{
	if (level == 0)
		return 0;
	if (level != 2)
		return -1;
	static constexpr uint8_t sig[12] = {0xd, 0xa, 0xd, 0xa, 0x0, 0xd, 0xa, 0x51, 0x55, 0x49, 0x54, 0xa};
	uint8_t buf[4096];
	if (HXio_fullread(fd, buf, 16) != 16)
		return -1;
	if (memcmp(buf, sig, sizeof(sig)) != 0)
		return -1;
	if (static_cast<unsigned int>((buf[12] & 0xF0) >> 4) != level || level != 2)
		return -1;
	if ((buf[12] & 0xF) == 0)
		return 0;
	if ((buf[12] & 0xF) != 1)
		return -1;
	uint16_t hlen = static_cast<uint16_t>(buf[14] << 8) | buf[15];
	switch (buf[13] & 0xF0) {
	case 0x10: {
		if (hlen != 12 || HXio_fullread(fd, buf, 12) != 12)
			return -1;
		auto peer = reinterpret_cast<sockaddr_in *>(ss);
		*peer = {};
		peer->sin_family = AF_INET;
		memcpy(&peer->sin_addr, &buf[0], sizeof(peer->sin_addr));
		memcpy(&peer->sin_port, &buf[8], sizeof(peer->sin_port));
		static_assert(sizeof(peer->sin_addr) == 4 && sizeof(peer->sin_port) == 2);
		return 0;
	}
	case 0x20: {
		if (hlen != 36 || HXio_fullread(fd, buf, 36) != 36)
			return -1;
		auto peer = reinterpret_cast<sockaddr_in6 *>(ss);
		*peer = {};
		peer->sin6_family = AF_INET6;
		memcpy(&peer->sin6_addr, &buf[0], sizeof(peer->sin6_addr));
		memcpy(&peer->sin6_port, &buf[32], sizeof(peer->sin6_port));
		static_assert(sizeof(peer->sin6_addr) == 16 && sizeof(peer->sin6_port) == 2);
		return 0;
	}
	case 0x30: {
		if (hlen != 216 || HXio_fullread(fd, buf, 216) != 216)
			return -1;
		auto peer = reinterpret_cast<sockaddr_un *>(ss);
		*peer = {};
		peer->sun_family = AF_LOCAL;
		memcpy(&peer->sun_path, &buf[0], std::min(static_cast<size_t>(108), sizeof(peer->sun_path)));
		return 0;
	}
	default:
		while (hlen > 0) {
			auto toread = std::min(static_cast<size_t>(hlen), sizeof(buf));
			auto ret = HXio_fullread(fd, buf, toread);
			if (ret < 0 || static_cast<size_t>(ret) != toread)
				return -1;
			hlen -= toread;
		}
		return 0;
	}
	return -1;
}

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
	auto cl_0 = make_scope_exit([&]() { freeaddrinfo(aires); });
	out = aires->ai_canonname;
	return 0;
} catch (const std::bad_alloc &) {
	return ENOMEM;
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
	set(nullptr, d.deflt);
}

void config_file::cfg_entry::set(const char *k, const char *sv)
{
	char *end = nullptr;
	if (m_flags & CFG_BOOL) {
		m_val = parse_bool(sv) ? "1" : "0";
	} else if (m_flags & CFG_TIME) {
		auto nv = HX_strtoull_sec(sv, &end);
		if (m_min.size() > 0)
			nv = std::max(nv, HX_strtoull_sec(m_min.c_str(), nullptr));
		if (m_max.size() > 0)
			nv = std::min(nv, HX_strtoull_sec(m_max.c_str(), nullptr));
		m_val = std::to_string(nv);
	} else if (m_flags & CFG_TIME_NS) {
#ifdef HAVE_LIBHX4_18
		auto nv = HX_strtoull_nsec(sv, &end);
		if (m_min.size() > 0)
			nv = std::max(nv, HX_strtoull_nsec(m_min.c_str(), nullptr));
		if (m_max.size() > 0)
			nv = std::min(nv, HX_strtoull_nsec(m_max.c_str(), nullptr));
#else
		auto nv = HX_strtoull_sec(sv, &end);
		if (m_min.size() > 0)
			nv = std::max(nv, HX_strtoull_sec(m_min.c_str(), nullptr));
		if (m_max.size() > 0)
			nv = std::min(nv, HX_strtoull_sec(m_max.c_str(), nullptr));
		nv *= 1000000000;
#endif
		m_val = std::to_string(nv);
	} else if (m_flags & CFG_SIZE) {
		auto nv = HX_strtoull_unit(sv, &end, 1024);
		if (m_min.size() > 0)
			nv = std::max(nv, HX_strtoull_unit(m_min.c_str(), nullptr, 1024));
		if (m_max.size() > 0)
			nv = std::min(nv, HX_strtoull_unit(m_max.c_str(), nullptr, 1024));
		m_val = std::to_string(nv);
	} else {
		m_val = sv;
	}
	if (k != nullptr && end != nullptr && *end != '\0')
		mlog(LV_ERR, "Config key \"%s\" value \"%s\" not fully accepted: "
			"error reportedly near >\"%s\"", k, sv, end);
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
			m_touched = true;
			return;
		} else if (i->second.m_flags & CFG_ALIAS) {
//			printf("\e[32m\t%s ...\e[0m\n", key, sv);
			key = i->second.m_val.c_str();
		} else {
//			printf("\e[32m\t%s = \e[1m%s\e[0m\n", key, sv);
			i->second.set(sk, sv);
			m_touched = true;
			return;
		}
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2367: ENOMEM");
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
	cfg->m_touched = false;
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

generic_connection::generic_connection(generic_connection &&o) :
	client_port(o.client_port), server_port(o.server_port),
	sockd(std::move(o.sockd)), ssl(std::move(o.ssl)),
	last_timestamp(o.last_timestamp)
{
	memcpy(client_ip, o.client_ip, sizeof(client_ip));
	memcpy(server_ip, o.server_ip, sizeof(server_ip));
	o.sockd = -1;
	o.ssl = nullptr;
}

generic_connection &generic_connection::operator=(generic_connection &&o)
{
	memcpy(client_ip, o.client_ip, sizeof(client_ip));
	memcpy(server_ip, o.server_ip, sizeof(server_ip));
	client_port = o.client_port;
	server_port = o.server_port;
	sockd = std::move(o.sockd);
	o.sockd = -1;
	ssl = std::move(o.ssl);
	o.ssl = nullptr;
	last_timestamp = o.last_timestamp;
	return *this;
}

generic_connection generic_connection::accept(int sv_sock,
    int haproxy, gromox::atomic_bool *stop_accept)
{
	generic_connection conn;
	struct sockaddr_storage sv_addr, cl_addr;
	socklen_t addrlen = sizeof(cl_addr);
	auto cl_sock = accept4(sv_sock, reinterpret_cast<struct sockaddr *>(&cl_addr),
	               &addrlen, SOCK_CLOEXEC);
	conn.sockd = cl_sock;
	if (*stop_accept) {
		conn.reset();
		conn.sockd = -2;
		return conn;
	} else if (cl_sock < 0) {
		conn.reset();
		return conn;
	}
	if (haproxy_intervene(cl_sock, haproxy, &cl_addr) < 0) {
		conn.reset();
		return conn;
	}
	char txtport[40];
	auto ret = getnameinfo(reinterpret_cast<sockaddr *>(&cl_addr), addrlen,
		   conn.client_ip, sizeof(conn.client_ip), txtport,
		   sizeof(txtport), NI_NUMERICHOST | NI_NUMERICSERV);
	if (ret != 0) {
		mlog(LV_WARN, "getnameinfo: %s\n", gai_strerror(ret));
		conn.reset();
		return conn;
	}
	conn.client_port = strtoul(txtport, nullptr, 0);
	addrlen = sizeof(sv_addr);
	ret = getsockname(cl_sock, reinterpret_cast<sockaddr *>(&sv_addr), &addrlen);
	if (ret != 0) {
		mlog(LV_WARN, "getsockname: %s\n", strerror(errno));
		conn.reset();
		return conn;
	}
	ret = getnameinfo(reinterpret_cast<sockaddr *>(&sv_addr), addrlen,
	      conn.server_ip, sizeof(conn.server_ip), txtport,
	      sizeof(txtport), NI_NUMERICHOST | NI_NUMERICSERV);
	if (ret != 0) {
		mlog(LV_WARN, "getnameinfo: %s\n", gai_strerror(ret));
		conn.reset();
		return conn;
	}
	conn.server_port = strtoul(txtport, nullptr, 0);
	conn.last_timestamp = tp_now();
	return conn;
}
