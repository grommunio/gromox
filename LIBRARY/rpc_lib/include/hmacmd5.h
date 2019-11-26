#ifndef _H_HMACMD5_
#define _H_HMACMD5_

#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdint.h>
#endif
#include <openssl/md5.h>

typedef struct _HMACMD5_CTX {
	MD5_CTX ctx;
	uint8_t k_ipad[65];    
	uint8_t k_opad[65];
} HMACMD5_CTX;

extern void hmacmd5_init(HMACMD5_CTX *ctx, const void *key, int key_len);
extern void hmacmd5_update(HMACMD5_CTX *ctx, const void *text, int text_len);
extern void hmacmd5_final(HMACMD5_CTX *ctx, void *digest);

#endif /* _H_HMACMD5_ */

