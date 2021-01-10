#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>

struct BINHEX {
	char file_name[64];
	uint32_t type;
	uint32_t creator;
	uint16_t flags;
	uint32_t data_len;
	uint8_t *pdata;
	uint32_t res_len;
	uint8_t *presource;
};

extern GX_EXPORT bool binhex_deserialize(BINHEX *, void *buf, uint32_t len);
void binhex_clear(BINHEX *pbinhex);
