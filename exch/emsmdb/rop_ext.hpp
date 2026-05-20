#pragma once
#include <cstdint>
#include <span>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapidefs.h>
#include "processor_types.hpp"

struct READRECEIPIENT_ROW;
struct notify_response;

extern pack_result rop_ext_pull(EXT_PULL &, ROP_BUFFER &);
extern pack_result rop_ext_make_rpc_ext(const void *pbuff_in, uint32_t in_len, const ROP_BUFFER *prop_buff, void *pbuff_out, uint32_t *pout_len);
void rop_ext_set_rhe_flag_last(uint8_t *pdata, uint32_t last_offset);
extern pack_result rop_push_ext(EXT_PUSH &, std::span<const gromox::proptag_t> cols, const READRECIPIENT_ROW &);
extern pack_result rop_ext_push(EXT_PUSH &, uint8_t logon_id, const rop_response &);
extern pack_result rop_ext_push(EXT_PUSH &, const notify_response &);
extern pack_result rop_ext_push(EXT_PUSH &, const PENDING_RESPONSE &);
