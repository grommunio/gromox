#pragma once
#include <cstdint>
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

BOOL binhex_deserialize(BINHEX *pbinhex,
	void *pbuff, uint32_t length);

void binhex_clear(BINHEX *pbinhex);
