#pragma once
#include <cstdint>
#include <memory>
#include <string_view>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <gromox/defs.h>

namespace gromox {

struct GX_EXPORT sslfree {
	STATIC_IN_CXX23 inline void operator()(EVP_CIPHER_CTX *x) CONST_BEFORE_CXX23 { EVP_CIPHER_CTX_free(x); }
	STATIC_IN_CXX23 inline void operator()(EVP_MD_CTX *x) CONST_BEFORE_CXX23 { EVP_MD_CTX_free(x); }
	STATIC_IN_CXX23 inline void operator()(EVP_PKEY *x) CONST_BEFORE_CXX23 { EVP_PKEY_free(x); }
};

extern GX_EXPORT int tls_set_min_proto(SSL_CTX *, const char *);
extern GX_EXPORT void tls_set_renego(SSL_CTX *);
extern GX_EXPORT std::string sss_obf_reverse(std::string_view);

}
