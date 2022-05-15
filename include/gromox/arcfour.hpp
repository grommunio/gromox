#pragma once
#include <cstdint>
#include <gromox/mapidefs.h>

struct ARCFOUR_STATE {
	uint8_t sbox[256];
	uint8_t index_i;
	uint8_t index_j;
};

void arcfour_init(ARCFOUR_STATE *pstate, const DATA_BLOB *pkey);
void arcfour_crypt_sbox(ARCFOUR_STATE *pstate, uint8_t *pdata, int len);
void arcfour_crypt(uint8_t *pdata, const uint8_t keystr[16], int len);
void arcfour_destroy(ARCFOUR_STATE *pstate);
