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

void D_P16(const uint8_t *p14, const uint8_t *in, uint8_t *out);

void E_old_pw_hash( uint8_t *p14, const uint8_t *in, uint8_t *out);

void des_crypt128(uint8_t out[8], const uint8_t in[8], const uint8_t key[16]);

void des_crypt64(uint8_t out[8], const uint8_t in[8], const uint8_t key[8], int forw);

void des_crypt112(uint8_t out[8], const uint8_t in[8], const uint8_t key[14], int forw);

void des_crypt112_16(uint8_t out[16], const uint8_t in[16], const uint8_t key[14], int forw);

void sam_rid_crypt(unsigned int rid, const uint8_t *in, uint8_t *out, int forw);

#ifdef __cplusplus
}
#endif
