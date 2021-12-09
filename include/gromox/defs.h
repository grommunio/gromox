#pragma once
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
namespace gromox {
template<typename T, size_t N> constexpr inline size_t arsizeof(T (&)[N]) { return N; }
#define GX_ARRAY_SIZE arsizeof
}
#define GX_EXPORT __attribute__((visibility("default")))
#define NOMOVE(K) \
	K(K &&) = delete; \
	void operator=(K &&) = delete;

enum gxerr_t {
	GXERR_SUCCESS = 0,
	GXERR_CALL_FAILED,
	GXERR_OVER_QUOTA,
};

enum ec_error_t {
	ecSuccess = 0,
	MAPI_E_DISK_FULL = 0x4,
	ecUnknownUser = 0x000003EB,
	ecServerOOM = 0x000003F0,
	ecLoginPerm = 0x000003F2,
	ecNotSearchFolder = 0x00000461,
	ecNoReceiveFolder = 0x00000463,
	ecWrongServer = 0x00000478,
	ecBufferTooSmall = 0x0000047D,
	ecSearchFolderScopeViolation = 0x00000490,
	ecRpcFormat = 0x000004B6,
	ecNullObject = 0x000004B9,
	ecQuotaExceeded = 0x000004D9,
	ecMaxAttachmentExceeded = 0x000004DB,
	ecNotExpanded = 0x000004F7,
	ecNotCollapsed = 0x000004F8,
	ecDstNullObject = 0x00000503,
	ecMsgCycle = 0x00000504,
	ecTooManyRecips = 0x00000505,
	RPC_X_BAD_STUB_DATA = 0x000006F7,
	ecRejected = 0x000007EE,
	ecWarnWithErrors = 0x00040380, /* MAPI_W_ERRORS_RETURNED */
	SYNC_W_CLIENT_CHANGE_NEWER = 0x00040821,
	// ecInterfaceNotSupported = 0x80004002, /* E_NOINTERFACE, MAPI_E_INTERFACE_NOT_SUPPORTED */
	ecError = 0x80004005, /* MAPI_E_CALL_FAILED */
	STG_E_ACCESSDENIED = 0x80030005, /* STG := "storage" */
	StreamSeekError = 0x80030019,
	ecInterfaceNotSupported = 0x80004002, /* E_NOINTERFACE, MAPI_E_INTERFACE_NOT_SUPPORTED */
	ecComputed = 0x8004011A, /* MAPI_E_COMPUTED */
	ecNotSupported = 0x80040102, /* MAPI_E_NO_SUPPORT */
	ecInvalidObject = 0x80040108, /* MAPI_E_INVALID_OBJECT */
	ecObjectModified = 0x80040109, /* MAPI_E_OBJECT_CHANGED */
	ecInsufficientResrc = 0x8004010E, /* MAPI_E_NOT_ENOUGH_RESOURCES */
	ecNotFound = 0x8004010F, /* MAPI_E_NOT_FOUND */
	ecLoginFailure = 0x80040111, /* MAPI_E_LOGON_FAILED */
	ecUnableToAbort = 0x80040114, /* MAPI_E_UNABLE_TO_ABORT */
	ecRpcFailed = 0x80040115, /* MAPI_E_NETWORK_ERROR */
	ecTooComplex = 0x80040117, /* MAPI_E_TOO_COMPLEX */
	MAPI_E_UNKNOWN_CPID = 0x8004011E,
	MAPI_E_UNKNOWN_LCID = 0x8004011F,
	ecTooBig = 0x80040305, /* MAPI_E_TOO_BIG */
	MAPI_E_DECLINE_COPY = 0x80040306,
	ecTableTooBig = 0x80040403, /* MAPI_E_TABLE_TOO_BIG */
	ecInvalidBookmark = 0x80040405, /* MAPI_E_INVALID_BOOKMARK */
	ecNotInQueue = 0x80040601, /* MAPI_E_NOT_IN_QUEUE */
	ecDuplicateName = 0x80040604, /* MAPI_E_COLLISION */
	ecNotInitialized = 0x80040605, /* MAPI_E_NOT_INITIALIZED */
	MAPI_E_FOLDER_CYCLE = 0x8004060B, /* MAPI_E_FOLDER_CYCLE */
	MAPI_E_STORE_FULL = 0x8004060C,
	EC_EXCEEDED_SIZE = 0x80040610,
	ecAmbiguousRecip = 0x80040700, /* MAPI_E_AMBIGUOUS_RECIP */
	SYNC_E_IGNORE = 0x80040801,
	SYNC_E_CONFLICT = 0x80040802,
	SYNC_E_NO_PARENT = 0x80040803,
	ecNPQuotaExceeded = 0x80040900, /* MAPI_E_NAMED_PROP_QUOTA_EXCEEDED */
	NotImplemented = 0x80040FFF, /* _not_ the same as ecNotSupported/ecNotImplemented/MAPI_E_NOT_IMPLEMENTED */
	ecAccessDenied = 0x80070005, /* MAPI_E_NO_ACCESS */
	ecMAPIOOM = 0x8007000E, /* MAPI_E_NOT_ENOUGH_MEMORY */
	ecInvalidParam = 0x80070057, /* MAPI_E_INVALID_PARAMETER */
};

enum gx_loglevel {
	LV_CRIT = 1,
	LV_ERR = 2,
	LV_WARN = 3,
	LV_NOTICE = 4,
	LV_INFO = 5,
	LV_DEBUG = 6,
};

enum {
	ULCLPART_SIZE = 65, /* localpart(64) plus \0 */
	UDOM_SIZE = 256, /* domain(255) plus \0 */
	UADDR_SIZE = 321, /* localpart(64) "@" domain \0 */

	/*
	 * The name of a namedprop can be at most 254 UTF-16 chars as per
	 * OXCPRPT v17 §4.1.1. Since Gromox operates in UTF-8, that's a few
	 * more octets. (TNEF uses a larger, 32-bit field.)
	 */
	GUIDSTR_SIZE = 37,
	NP_NAMEBUF_SIZE = 763,
	NP_STRBUF_SIZE = 36 + 11 + NP_NAMEBUF_SIZE, /* "GUID=<>,NAME=<>" */
};

extern GX_EXPORT unsigned int gxerr_to_hresult(gxerr_t);
extern GX_EXPORT const char *mapi_strerror(unsigned int);

template<typename T> constexpr T *deconst(const T *x) { return const_cast<T *>(x); }
#undef roundup /* you naughty glibc */
template<typename T> constexpr T roundup(T x, T y) { return (x + y - 1) / y * y; }
template<typename T, typename U> constexpr auto strange_roundup(T x, U y) -> decltype(x / y) { return (x / y + 1) * y; }
#define SR_GROW_ATTACHMENT_CONTENT 20U
#define SR_GROW_EID_ARRAY 100U
#define SR_GROW_PROPTAG_ARRAY 100U
#define SR_GROW_TAGGED_PROPVAL 100U
#define SR_GROW_TPROPVAL_ARRAY 100U

#ifdef COMPILE_DIAG
/* snprintf takes about 2.65x the time */
#define gx_strlcpy(dst, src, dsize) snprintf((dst), (dsize), "%s", (src))
#else
#define gx_strlcpy(dst, src, dsize) HX_strlcpy((dst), (src), (dsize))
#endif

static inline constexpr bool is_nameprop_id(unsigned int i) { return i >= 0x8000 && i <= 0xFFFE; }

namespace gromox {

struct stdlib_delete {
	inline void operator()(void *x) const { free(x); }
};
static inline const char *snul(const std::string &s) { return s.size() != 0 ? s.c_str() : nullptr; }
static inline const char *znul(const char *s) { return s != nullptr ? s : ""; }

}
