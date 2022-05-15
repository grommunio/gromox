// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstring>
#include <memory>
#include <gromox/cryptoutil.hpp>

using namespace gromox;

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
