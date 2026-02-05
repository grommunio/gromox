// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021–2026 grommunio GmbH
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
#include <memory>
#include <mutex>
#include <netdb.h>
#include <pwd.h>
#include <spawn.h>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>
#include <vector>
#ifdef HAVE_SYSLOG_H
#	include <syslog.h>
#endif
#include <json/reader.h>
#include <json/writer.h>
#include <libHX/ctype_helper.h>
#include <libHX/defs.h>
#include <libHX/io.h>
#include <libHX/proc.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <vmime/charset.hpp>
#include <gromox/archive.hpp>
#include <gromox/atomic.hpp>
#include <gromox/clock.hpp>
#include <gromox/config_file.hpp>
#include <gromox/cookie_parser.hpp>
#include <gromox/fileio.h>
#include <gromox/generic_connection.hpp>
#include <gromox/json.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapierr.hpp>
#include <gromox/paths.h>
#include <gromox/process.hpp>
#include <gromox/range_set.hpp>
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

static unsigned int g_max_loglevel = MLOG_DEFAULT_LEVEL;
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

const char *mapi_strerror(ec_error_t e)
{
	// STG = storage
#ifdef COMPILE_DIAG
	switch (static_cast<uint32_t>(e))
#else
	switch (e)
#endif
{
#define E(v, s) case v: return s;
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
		snprintf(xbuf, sizeof(xbuf), "Unknown MAPI error code %xh", static_cast<uint32_t>(e));
		return xbuf;
	}
	}
#undef E
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
			if (HX_isprint(data[i])) {
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
	bin2txt_init() {
		auto p = znul(getenv("BIN2TXT_MODE"));
		if (*p == '\0' || strcasecmp(p, "txt") == 0)
			m_cstr = 0;
		else if (strcasecmp(p, "hex") == 0)
			m_cstr = 1;
		else if (strcasecmp(p, "co") == 0 || strcasecmp(p, "cstr") == 0)
			m_cstr = 2;
	}
	unsigned int m_cstr = 0;
};
static bin2txt_init g_bin2txt_choice;
}

std::string bin2txt(const void *vdata, size_t len)
{
	switch (g_bin2txt_choice.m_cstr) {
	case 1: return bin2hex(vdata, len);
	case 2: return bin2cstr(vdata, len);
	}
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
		} else if (HX_isprint(data[i]) && data[i] != '^') {
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

static std::string banner_for_core;

void startup_banner(const char *prog)
{
	/*
	 * Readonly data like string literals is not replicated in coredumps;
	 * copy them to a writable memory region.
	 */
	auto &bfc = banner_for_core;
	size_t z_osrel = 0, z_arch = 0;
	std::unique_ptr<char[], stdlib_delete> osrel(HX_slurp_file("/etc/os-release", &z_osrel));
	std::unique_ptr<char[], stdlib_delete> arch(HX_slurp_file("/proc/sys/kernel/arch", &z_arch));
	bfc = "#PROG-ID\n"s + prog + " " + PACKAGE_VERSION + "\n#OSREL\n";
	if (osrel != nullptr) {
		bfc.append(osrel.get(), z_osrel);
		bfc += '\n';
	}
	bfc += "#ARCH\n";
	if (arch != nullptr) {
		bfc.append(arch.get(), z_arch);
		bfc += '\n';
	}

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

bool setup_utf8_locale()
{
	if (setlocale(LC_ALL, "C.UTF-8") != nullptr && iswalnum(0x79C1))
		return true;
	if (setlocale(LC_ALL, "en_US.UTF-8") != nullptr)
		return true;
	mlog(LV_INFO, "Could not set the program to UTF-8 locale. "
		"Text operations, e.g. PR_SUBJECT_PREFIX extraction, may fail to produce results.");
	return false;
}

int iconv_validate()
{
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

bool get_digest(const Json::Value &jval, const char *key, std::string &out) try
{
	if (jval.type() != Json::ValueType::objectValue || !jval.isMember(key))
		return false;
	out = jval[key].asString();
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return false;
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
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return false;
}

bool get_digest(const char *json, const char *key, char *out, size_t outmax) try
{
	Json::Value jval;
	if (!gromox::str_to_json(json, jval))
		return false;
	return get_digest(jval, key, out, outmax);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return false;
}

template<typename T> static bool
set_digest2(char *json, size_t iomax, const char *key, T &&val) try
{
	Json::Value jval;
	if (!gromox::str_to_json(json, jval))
                return false;
	jval[key] = val;
	Json::StreamWriterBuilder swb;
	swb["indentation"] = "";
	gx_strlcpy(json, Json::writeString(swb, std::move(jval)).c_str(), iomax);
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
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

void mlog_init(const char *ident, const char *filename, unsigned int max_level,
    const char *user)
{
	g_max_loglevel = max_level;
	bool for_syslog = false, for_tty = false;
	if (filename == nullptr || *filename == '\0' || strcmp(filename, "-") == 0) {
		if (isatty(STDERR_FILENO))
			for_tty = true;
		else if (getppid() == 1 && getenv("JOURNAL_STREAM") != nullptr)
			for_syslog = true;
		else
			for_tty = true;
	} else if (strcmp(filename, "syslog") == 0) {
		for_syslog = true;
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

bool str_to_json(std::string_view sv, Json::Value &jv)
{
	using reader_t = decltype(Json::CharReaderBuilder().newCharReader());
	std::unique_ptr<std::remove_pointer_t<reader_t>> rd(Json::CharReaderBuilder().newCharReader());
	return rd->parse(sv.data(), sv.data() + sv.size(), &jv, nullptr);
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
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ENOMEM;
}

/**
 * @h:  PR_MESSAGE_CLASS/PR_CONTAINER_CLASS value
 * @n:  prefix to test for
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
 * @h:  PR_MESSAGE_CLASS/PR_CONTAINER_CLASS value
 * @n:  suffix to test for
 *
 * On match, 0 is returned; otherwise anything non-zero.
 * This function is not meant for testing for root classes like "IPM".
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
			if (iscntrl(static_cast<unsigned char>(*p)) && !HX_isspace(*p))
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

/**
 * Callers might expect to see std::bad_alloc, so for now, let such exception
 * escape without conversion to ENOMEM. Callers should ideally check for ENOMEM
 * anyway.
 */
std::string iconvtext(std::string_view sv,
    const char *from, const char *to, unsigned int flags) try
{
	if (strcasecmp(from, to) == 0) {
		errno = 0;
		return std::string(sv);
	}
	auto cd = iconv_open(to, from);
	if (cd == reinterpret_cast<iconv_t>(-1)) {
		mlog(LV_ERR, "E-2116: iconv_open(%s -> %s): %s", from, to, strerror(errno));
		errno = EINVAL;
		return {};
	}
	try {
		char buffer[4096];
		std::string out;
		bool last_bad = false;
		auto src = deconst(sv.data());
		size_t src_size = sv.size();

		while (src_size > 0) {
			auto dst = buffer;
			size_t dst_size = sizeof(buffer);
			errno = 0;
			auto ret = iconv(cd, &src, &src_size, &dst, &dst_size);
			if (dst_size != sizeof(buffer)) {
				last_bad = false;
				out.append(buffer, sizeof(buffer) - dst_size);
			}
			if (ret != (size_t)-1 || src_size == 0) {
				last_bad = false;
				continue;
			}
			if (errno == EILSEQ || errno == EINVAL) {
				--src_size;
				++src;
				if (flags & ICONVTEXT_TRANSLIT) {
					if (!last_bad)
						out += '?';
					last_bad = true;
				}
			}
		}

		/* Flush pending shift and/or state */
		auto dst = buffer;
		size_t dst_size = sizeof(buffer);
		errno = 0;
		auto ret = iconv(cd, nullptr, 0, &dst, &dst_size);
		if (dst_size != sizeof(buffer))
			out.append(buffer, sizeof(buffer) - dst_size);
		if (ret != (size_t)-1 || src_size == 0) {
		} else if (errno == EILSEQ || errno == EINVAL) {
			if (flags & ICONVTEXT_TRANSLIT)
				out += '?';
		}
		errno = 0;
		iconv_close(cd);
		return out;
	} catch (const std::bad_alloc &) {
		iconv_close(cd);
		errno = ENOMEM;
		return {};
	}
} catch (const std::bad_alloc &) {
	errno = ENOMEM;
	return {};
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

bool str_isascii(const char *s)
{
	for (; *s != '\0'; ++s)
		if (!HX_isascii(static_cast<unsigned char>(*s)))
			return false;
	return true;
}

bool str_isasciipr(const char *s)
{
	for (; *s != '\0'; ++s) {
		unsigned char c = *s;
		if (!HX_isascii(c) && !HX_isprint(c))
			return false;
	}
	return true;
}

int ece2nerrno(ec_error_t e)
{
#ifdef COMPILE_DIAG
	switch (static_cast<uint32_t>(e))
#else
	switch (e)
#endif
	{
	case ecSuccess: return 0;
	case ecMAPIOOM: [[fallthrough]];
	case ecServerOOM: return -ENOMEM;
	case ecInvalidParam: return -EINVAL;
	case ecNotFound: return -ENOENT;
	default: return -EIO;
	}
}

static std::string cookie_rmeta(std::string_view sv)
{
	std::string s{sv};
	auto o = s.begin();
	for (auto i = s.begin(); i < s.end(); ++i) {
		if (*i != '%') {
			*o++ = *i;
			continue;
		}
		if (i + 1 == s.end() || i + 2 == s.end())
			break;
		char tb[3] = {i[1], i[2], '\0'};
		char *end = nullptr;
		uint8_t c = strtoul(tb, &end, 16);
		if (end == &tb[2])
			*o++ = c;
		i += 2;
	}
	s.erase(o, s.end());
	return s;
}

static inline size_t sv_cspn(std::string_view sv, char c)
{
	auto p = sv.find(c);
	return p != sv.npos ? p : sv.size();
}

ec_error_t cookie_jar::add(std::string_view sv) try
{
	while (sv.size() > 0) {
		while (sv.size() > 0 && HX_isspace(sv[0]))
			sv.remove_prefix(1);
		auto klen = sv.find_first_of(";=");
		if (klen == sv.npos)
			klen = sv.size();
		auto &value = emplace(sv.substr(0, klen), std::string()).first->second;
		sv.remove_prefix(klen);
		if (sv.size() == 0)
			break; /* attribute without cookie-value */
		if (sv[0] != '=') {
			sv.remove_prefix(1); /* ; */
			continue;
		}
		sv.remove_prefix(1); /* = */
		if (sv.size() == 0)
			break;
		size_t vlen;
		if (sv[0] == '"') {
			sv.remove_prefix(1);
			vlen  = sv_cspn(sv, '\"');
			value = cookie_rmeta(sv.substr(0, vlen));
			sv.remove_prefix(vlen);
			vlen  = sv_cspn(sv, ';');
		} else {
			vlen  = sv_cspn(sv, ';');
			value = cookie_rmeta(sv.substr(0, vlen));
		}
		sv.remove_prefix(vlen);
		if (sv.size() > 0)
			sv.remove_prefix(1); /* ; */
	}
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

const char *cookie_jar::operator[](const char *name) const
{
	auto i = map::find(name);
	return i != cend() ? i->second.c_str() : nullptr;
}

std::vector<std::string> gx_split(std::string_view sv, char sep)
{
	size_t start = 0, pos;
	std::vector<std::string> out;
	while ((pos = sv.find(sep, start)) != sv.npos) {
		out.emplace_back(sv.substr(start, pos - start));
		start = pos + 1;
	}
	out.emplace_back(sv.substr(start));
	return out;
}

std::vector<std::string> gx_split_ws(std::string_view sv, char sep)
{
	size_t start = 0, pos;
	std::vector<std::string> out;
	while ((pos = sv.find(sep, start)) != sv.npos) {
		out.emplace_back(sv.substr(start, pos - start));
		start = sv.find_first_not_of(sep, pos + 1);
	}
	out.emplace_back(sv.substr(start));
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
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
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
	auto cl_0 = HX::make_scope_exit([&]() { HXmc_free(line); });
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
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	errno = ENOMEM;
	return nullptr;
}

/**
 * Convert Unicode code point @wchar to its UTF-8 representation.
 */
std::string wchar_to_utf8(uint32_t w)
{
	std::string s;
	if (w <= 0x7f) {
		s.resize(1);
		s[0] = w;
	} else if (w <= 0x7ff) {
		s.resize(2);
		s[0] = 192 + w / 64;
		s[1] = 128 + w % 64;
	} else if (w <= 0xffff) {
		s.resize(3);
		s[0] = 224 + w / 4096;
		s[1] = 128 + w / 64 % 64;
		s[2] = 128 + w % 64;
	} else if (w <= 0x10ffff) {
		s.resize(4);
		s[0] = 240 + w / 262144;
		s[1] = 128 + w / 4096 % 64;
		s[2] = 128 + w / 64 % 64;
		s[3] = 128 + w % 64;
	} else {
		s.resize(3);
		w = 0xfffd;
		s[0] = 224 + w / 4096;
		s[1] = 128 + w / 64 % 64;
		s[2] = 128 + w % 64;
	}
	return s;
}
