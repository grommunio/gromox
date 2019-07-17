#ifndef _H_HMACMD5_
#define _H_HMACMD5_
#include <stdint.h>
#include <openssl/md5.h>

typedef struct _HMACMD5_CTX {
	MD5_CTX ctx;
	uint8_t k_ipad[65];    
	uint8_t k_opad[65];
} HMACMD5_CTX;

void hmacmd5_init(HMACMD5_CTX *ctx, const uint8_t *key, int key_len);

void hmacmd5_update(HMACMD5_CTX *ctx, const uint8_t *text, int text_len);

void hmacmd5_final(HMACMD5_CTX *ctx, uint8_t *digest);

#endif /* _H_HMACMD5_ */

