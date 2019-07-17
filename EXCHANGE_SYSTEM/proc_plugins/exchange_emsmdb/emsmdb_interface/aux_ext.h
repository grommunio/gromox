#ifndef _H_AUX_EXT_
#define _H_AUX_EXT_
#include "ext_buffer.h"
#include "aux_types.h"

int aux_ext_pull_aux_info(EXT_PULL *pext, AUX_INFO *r);

int aux_ext_push_aux_info(EXT_PUSH *pext, AUX_INFO *r);

#endif /* _H_AUX_EXT_ */
