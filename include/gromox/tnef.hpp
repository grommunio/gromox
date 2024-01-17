#pragma once
#include <cstdint>
#include <gromox/ext_buffer.hpp>

struct message_content;

extern void tnef_init_library();
extern message_content *tnef_deserialize(const void *buf,
	uint32_t length, EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
	USERNAME_TO_ENTRYID username_to_entryid);
extern BINARY *tnef_serialize(const message_content *,
	EXT_BUFFER_ALLOC alloc, GET_PROPNAME get_propname);
