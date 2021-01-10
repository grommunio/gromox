#pragma once
#include <cstdint>
#include <openssl/md5.h>

struct HMACMD5_CTX {
	MD5_CTX ctx;
	uint8_t k_ipad[65];    
	uint8_t k_opad[65];
};

extern void hmacmd5_init(HMACMD5_CTX *ctx, const void *key, int key_len);
extern void hmacmd5_update(HMACMD5_CTX *ctx, const void *text, int text_len);
extern void hmacmd5_final(HMACMD5_CTX *ctx, void *digest);
