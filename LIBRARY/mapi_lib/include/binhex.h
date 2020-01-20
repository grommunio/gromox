#pragma once
#include "mapi_types.h"

typedef struct _BINHEX {
	char file_name[64];
	uint32_t type;
	uint32_t creator;
	uint16_t flags;
	uint32_t data_len;
	uint8_t *pdata;
	uint32_t res_len;
	uint8_t *presource;
} BINHEX;

#ifdef __cplusplus
extern "C" {
#endif

BOOL binhex_deserialize(BINHEX *pbinhex,
	void *pbuff, uint32_t length);

void binhex_clear(BINHEX *pbinhex);

BINARY* binhex_serialize(const BINHEX *pbinhex);

#ifdef __cplusplus
}
#endif
