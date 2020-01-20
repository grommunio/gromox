#pragma once
#include "element_data.h"
#include "ext_buffer.h"


#ifdef __cplusplus
extern "C" {
#endif

void tnef_init_library(CPID_TO_CHARSET cpid_to_charset);

MESSAGE_CONTENT* tnef_deserialize(const void *pbuff,
	uint32_t length, EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
	USERNAME_TO_ENTRYID username_to_entryid);

BINARY* tnef_serialize(const MESSAGE_CONTENT *pmsg,
	EXT_BUFFER_ALLOC alloc, GET_PROPNAME get_propname);

#ifdef __cplusplus
}
#endif
