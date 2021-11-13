#pragma once
#include <gromox/ext_buffer.hpp>

struct AUX_INFO;
int aux_ext_pull_aux_info(EXT_PULL *pext, AUX_INFO *r);
int aux_ext_push_aux_info(EXT_PUSH *pext, AUX_INFO *r);
