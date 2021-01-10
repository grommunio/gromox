#pragma once
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>

void tnef_init_library(CPID_TO_CHARSET cpid_to_charset);

MESSAGE_CONTENT* tnef_deserialize(const void *pbuff,
	uint32_t length, EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
	USERNAME_TO_ENTRYID username_to_entryid);

BINARY* tnef_serialize(const MESSAGE_CONTENT *pmsg,
	EXT_BUFFER_ALLOC alloc, GET_PROPNAME get_propname);
