// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2021-2022 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstring>
#include <memory>
#include <string_view>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <gromox/cryptoutil.hpp>
#include <gromox/endian.hpp>

namespace gromox {

/* the microsoft version of hmac_md5 initialisation */
HMACMD5_CTX::HMACMD5_CTX(const void *key, size_t key_len) :
	osslctx(EVP_MD_CTX_new())
{
	if (osslctx == nullptr)
		return;
	if (key_len > 64)
		key_len = 64;
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);
	/* XOR key with ipad and opad values */
	for (size_t i = 0; i < 64; ++i) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}
	if (EVP_DigestInit(osslctx.get(), EVP_md5()) <= 0 ||
	    EVP_DigestUpdate(osslctx.get(), k_ipad, 64) <= 0)
		return;
	valid_flag = true;
}

bool HMACMD5_CTX::update(const void *text, size_t text_len)
{
	return EVP_DigestUpdate(osslctx.get(), text, text_len) > 0;
}

bool HMACMD5_CTX::finish(void *digest)
{
	decltype(osslctx) ctx_o(EVP_MD_CTX_new());
	if (ctx_o == nullptr ||
	    EVP_DigestFinal(osslctx.get(), static_cast<uint8_t *>(digest), nullptr) <= 0 ||
	    EVP_DigestInit(ctx_o.get(), EVP_md5()) <= 0 ||
	    EVP_DigestUpdate(ctx_o.get(), k_opad, 64) <= 0 ||
	    EVP_DigestUpdate(ctx_o.get(), digest, 16) <= 0 ||
	    EVP_DigestFinal(ctx_o.get(), static_cast<uint8_t *>(digest), nullptr) <= 0)
		return false;
	return true;
}

int tls_set_min_proto(SSL_CTX *ctx, const char *p)
{
	if (p == nullptr)
		return 0;
#if defined(LIBRESSL_VERSION_NUMBER) || (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L)
	if (strcmp(p, "tls1.3") == 0)
#ifdef TLS1_3_VERSION
		SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
#else
		return -1;
#endif
	else if (strcmp(p, "tls1.2") == 0)
		SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	else if (strcmp(p, "tls1.1") == 0)
		SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);
	else if (strcmp(p, "tls1.0") == 0)
		SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
	else
		return -1;
#else
	if (strcmp(p, "tls1.0") == 0)
		SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
	else if (strcmp(p, "tls1.1") == 0)
		SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
	else if (strcmp(p, "tls1.2") == 0)
		SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
	else if (strcmp(p, "tls1.3") == 0)
		SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2);
	else
		return -1;
#endif
	return 0;
}

std::string sss_obf_reverse(const std::string_view &x)
{
	std::string out;
	auto z = x.size();
	if (z < 6 || x[z-4] != '\0' || x[z-3] != '\1' ||
	    x[z-2] != '\2' || x[z-1] != '\3')
		return out;
	auto meth = le16p_to_cpu(&x[0]);
	if (meth != 0 || x.size() < 4+32+16+4)
		return out;
	std::unique_ptr<EVP_CIPHER_CTX, sslfree> ctx(EVP_CIPHER_CTX_new());

#define CU(x) reinterpret_cast<const unsigned char *>(x)
#define U(x) reinterpret_cast<unsigned char *>(x)
	auto cipher = EVP_get_cipherbynid(NID_aes_256_cbc);
	if (cipher == nullptr ||
	    !EVP_DecryptInit_ex(ctx.get(), cipher, 0, CU(&x[4]), CU(&x[36])))
		return out;
	out.resize(x.size() - 56);
	int plainlen = 0, digestlen = 0;
	if (!EVP_DecryptUpdate(ctx.get(), U(&out[0]), &plainlen,
	    CU(&x[52]), x.size() - 56) ||
	    !EVP_DecryptFinal_ex(ctx.get(), U(&out[plainlen]), &digestlen))
		return {};
	out.resize(plainlen + digestlen);
	return out;
#undef U
#undef CU
}

}
