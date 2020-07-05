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
	ecError = 0x80004005,
	ecNotSupported = 0x80040102,
	ecInvalidParam = 0x80070057,
};

#ifdef __cplusplus
extern "C" {
#endif

extern GX_EXPORT unsigned int gxerr_to_hresult(gxerr_t);

#ifdef __cplusplus
} /* extern "C" */
#endif
