#pragma once
#include <cstdint>
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>

extern void tnef_init_library();
MESSAGE_CONTENT* tnef_deserialize(const void *pbuff,
	uint32_t length, EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
	USERNAME_TO_ENTRYID username_to_entryid);
BINARY* tnef_serialize(const MESSAGE_CONTENT *pmsg,
	EXT_BUFFER_ALLOC alloc, GET_PROPNAME get_propname);
