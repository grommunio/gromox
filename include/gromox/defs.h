#pragma once
#include <endian.h>
#include <cstddef>
#include <cstdint>
template<typename T, size_t N> constexpr inline size_t GX_ARRAY_SIZE(T (&)[N]) { return N; }
#define GX_EXPORT __attribute__((visibility("default")))

#if (defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN) || \
    (defined(_BYTE_ORDER) && _BYTE_ORDER == _BIG_ENDIAN)
#	define cpu_to_le16(x) __builtin_bswap16(x)
#	define cpu_to_le32(x) __builtin_bswap32(x)
#	define cpu_to_le64(x) __builtin_bswap64(x)
#	define cpu_to_be16(x) ((uint16_t)(x))
#	define cpu_to_be32(x) ((uint32_t)(x))
#	define cpu_to_be64(x) ((uint64_t)(x))
#	define le16_to_cpu(x) __builtin_bswap16(x)
#	define le32_to_cpu(x) __builtin_bswap32(x)
#	define le64_to_cpu(x) __builtin_bswap64(x)
#	define be16_to_cpu(x) ((uint16_t)(x)
#	define be32_to_cpu(x) ((uint32_t)(x)
#	define be64_to_cpu(x) ((uint64_t)(x)
#else
#	define cpu_to_le16(x) (x)
#	define cpu_to_le32(x) (x)
#	define cpu_to_le64(x) (x)
#	define cpu_to_be16(x) __builtin_bswap16(x)
#	define cpu_to_be32(x) __builtin_bswap32(x)
#	define cpu_to_be64(x) __builtin_bswap64(x)
#	define le16_to_cpu(x) (x)
#	define le32_to_cpu(x) (x)
#	define le64_to_cpu(x) (x)
#	define be16_to_cpu(x) __builtin_bswap16(x)
#	define be32_to_cpu(x) __builtin_bswap32(x)
#	define be64_to_cpu(x) __builtin_bswap64(x)
#endif

typedef enum {
	GXERR_SUCCESS = 0,
	GXERR_CALL_FAILED,
	GXERR_OVER_QUOTA,
} gxerr_t;

enum {
	ecSuccess = 0,
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
	ecWarnWithErrors = 0x00040380,
	SYNC_W_CLIENT_CHANGE_NEWER = 0x00040821,
	ecError = 0x80004005,
	STG_E_ACCESSDENIED = 0x80030005,
	StreamSeekError = 0x80030019,
	ecNotSupported = 0x80040102,
	ecInvalidObject = 0x80040108,
	ecObjectModified = 0x80040109,
	ecInsufficientResrc = 0x8004010E,
	ecNotFound = 0x8004010F,
	ecLoginFailure = 0x80040111,
	ecUnableToAbort = 0x80040114,
	ecRpcFailed = 0x80040115,
	ecTooComplex = 0x80040117,
	MAPI_E_UNKNOWN_CPID = 0x8004011E,
	MAPI_E_UNKNOWN_LCID = 0x8004011F,
	ecTooBig = 0x80040305,
	MAPI_E_DECLINE_COPY = 0x80040306,
	ecTableTooBig = 0x80040403,
	ecInvalidBookmark = 0x80040405,
	ecNotInQueue = 0x80040601,
	ecDuplicateName = 0x80040604,
	ecNotInitialized = 0x80040605,
	MAPI_E_FOLDER_CYCLE = 0x8004060B,
	EC_EXCEEDED_SIZE = 0x80040610,
	ecAmbiguousRecip = 0x80040700,
	SYNC_E_IGNORE = 0x80040801,
	SYNC_E_CONFLICT = 0x80040802,
	SYNC_E_NO_PARENT = 0x80040803,
	NotImplemented = 0x80040FFF,
	ecAccessDenied = 0x80070005,
	ecMAPIOOM = 0x8007000E,
	ecInvalidParam = 0x80070057,
};

extern GX_EXPORT unsigned int gxerr_to_hresult(gxerr_t);
extern GX_EXPORT const char *mapi_strerror(unsigned int);

template<typename T> constexpr T *deconst(const T *x) { return const_cast<T *>(x); }
#undef roundup /* you naughty glibc */
template<typename T> constexpr T roundup(T x, T y) { return (x + y - 1) / y * y; }
