#pragma once
#include <cstdint>
#include <memory>
#include <string_view>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <gromox/defs.h>

namespace gromox {

struct GX_EXPORT sslfree {
	inline void operator()(EVP_CIPHER_CTX *x) const { EVP_CIPHER_CTX_free(x); }
	inline void operator()(EVP_MD_CTX *x) const { EVP_MD_CTX_free(x); }
};

extern GX_EXPORT int tls_set_min_proto(SSL_CTX *, const char *);
extern GX_EXPORT void tls_set_renego(SSL_CTX *);
extern GX_EXPORT std::string sss_obf_reverse(const std::string_view &);

}
