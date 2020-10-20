#pragma once
#include "ext_buffer.h"
#include "aux_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int aux_ext_pull_aux_info(EXT_PULL *pext, AUX_INFO *r);

int aux_ext_push_aux_info(EXT_PUSH *pext, AUX_INFO *r);

#ifdef __cplusplus
} /* extern "C" */
#endif
