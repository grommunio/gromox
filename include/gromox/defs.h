#pragma once
#ifndef __cplusplus
#	define nullptr NULL
#endif
#define GX_EXPORT __attribute__((visibility("default")))
typedef enum {
	GXERR_SUCCESS = 0,
	GXERR_CALL_FAILED,
	GXERR_OVER_QUOTA,
} gxerr_t;

enum {
	ecSuccess = 0,
	ecNullObject = 0x000004B9,
	ecWarnWithErrors = 0x00040380,
	ecError = 0x80004005,
	ecNotSupported = 0x80040102,
	ecInvalidObject = 0x80040108,
	ecNotFound = 0x8004010F,
	ecRpcFailed = 0x80040115,
	MAPI_E_UNKNOWN_CPID = 0x8004011E,
	MAPI_E_DECLINE_COPY = 0x80040306,
	ecDuplicateName = 0x80040604,
	SYNC_E_IGNORE = 0x80040801,
	SYNC_E_CONFLICT = 0x80040802,
	SYNC_E_NO_PARENT = 0x80040803,
	ecAccessDenied = 0x80070005,
	ecMAPIOOM = 0x8007000E,
	ecInvalidParam = 0x80070057,
};

#ifdef __cplusplus
extern "C" {
#endif

extern GX_EXPORT unsigned int gxerr_to_hresult(gxerr_t);

#ifdef __cplusplus
} /* extern "C" */
#endif
