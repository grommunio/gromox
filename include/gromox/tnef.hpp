#pragma once
#include <cstdint>
#include <gromox/ext_buffer.hpp>

struct message_content;

extern GX_EXPORT message_content *tnef_deserialize(const void *buf, uint32_t len, EXT_BUFFER_ALLOC, GET_PROPIDS, USERNAME_TO_ENTRYID);
extern GX_EXPORT BINARY *tnef_serialize(const message_content *, const char *log_id, EXT_BUFFER_ALLOC, GET_PROPNAME) __attribute__((nonnull(2)));
