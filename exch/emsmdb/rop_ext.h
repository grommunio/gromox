#pragma once
#include <cstdint>
#include <gromox/ext_buffer.hpp>
#include "processor_types.h"

extern pack_result rop_ext_pull_rop_buffer(EXT_PULL *, ROP_BUFFER *);
extern pack_result rop_ext_make_rpc_ext(const void *pbuff_in, uint32_t in_len, const ROP_BUFFER *prop_buff, void *pbuff_out, uint32_t *pout_len);
void rop_ext_set_rhe_flag_last(uint8_t *pdata, uint32_t last_offset);
extern pack_result rop_ext_push_rop_response(EXT_PUSH *, uint8_t logon_id, ROP_RESPONSE *);
extern pack_result rop_ext_push_notify_response(EXT_PUSH *, const NOTIFY_RESPONSE *);
extern pack_result rop_ext_push_pending_response(EXT_PUSH *, const PENDING_RESPONSE *);
