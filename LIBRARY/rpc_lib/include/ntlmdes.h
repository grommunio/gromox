#pragma once
#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

void des_crypt56(uint8_t out[8], const uint8_t in[8], const uint8_t key[7], int forw);
extern void E_P16(const void *p14, uint8_t *p16);
void E_P24(const uint8_t *p21, const uint8_t *c8, uint8_t *p24);

#ifdef __cplusplus
}
#endif
