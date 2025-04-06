#pragma once
#include <cstdint>
#include <gromox/mapidefs.h>

struct GX_EXPORT ARCFOUR_STATE {
	uint8_t sbox[256];
	uint8_t index_i;
	uint8_t index_j;
};

extern GX_EXPORT void arcfour_init(ARCFOUR_STATE *pstate, const uint8_t *key, size_t keylen);
extern GX_EXPORT void arcfour_crypt_sbox(ARCFOUR_STATE *pstate, uint8_t *pdata, int len);
extern GX_EXPORT void arcfour_crypt(uint8_t *pdata, const uint8_t keystr[16], int len);
