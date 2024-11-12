#pragma once
#include <cstdint>
#include <gromox/ext_buffer.hpp>

struct message_content;

extern GX_EXPORT void tnef_init_library();
extern GX_EXPORT message_content *tnef_deserialize(const void *buf, uint32_t len, EXT_BUFFER_ALLOC, GET_PROPIDS, USERNAME_TO_ENTRYID);
extern GX_EXPORT BINARY *tnef_serialize(const message_content *, EXT_BUFFER_ALLOC, GET_PROPNAME);
