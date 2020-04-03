#pragma once
#ifndef __cplusplus
#	define nullptr NULL
#endif
#define GX_EXPORT __attribute__((visibility("default")))
typedef enum {
	GXERR_SUCCESS = 0,
	GXERR_CALL_FAILED,
} gxerr_t;

#ifdef __cplusplus
extern "C" {
#endif

extern GX_EXPORT unsigned int gxerr_to_hresult(gxerr_t);

#ifdef __cplusplus
} /* extern "C" */
#endif
