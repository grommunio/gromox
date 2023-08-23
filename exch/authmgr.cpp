// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#define DECLARE_SVC_API_STATIC
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>
#include <libHX/io.h>
#include <libHX/string.h>
#include <openssl/bio.h>
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
#	include <openssl/decoder.h>
#endif
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <gromox/authmgr.hpp>
#include <gromox/common_types.hpp>
#include <gromox/config_file.hpp>
#include <gromox/cryptoutil.hpp>
#include <gromox/fileio.h>
#include <gromox/json.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/paths.h>
#include <gromox/svc_common.h>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>
#include "ldap_adaptor.hpp"

using namespace std::string_literals;
using namespace gromox;
enum { A_DENY_ALL, A_ALLOW_ALL, A_EXTERNID };

namespace {
struct sslfree2 : public sslfree {
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
	inline void operator()(OSSL_DECODER_CTX *x) const { OSSL_DECODER_CTX_free(x); }
#endif
	inline void operator()(BIO *x) const { BIO_free(x); }
	inline void operator()(EVP_PKEY *x) const { EVP_PKEY_free(x); }
};
}

static decltype(mysql_adaptor_meta) *fptr_mysql_meta;
static decltype(mysql_adaptor_login2) *fptr_mysql_login;
static decltype(ldap_adaptor_login3) *fptr_ldap_login;
static unsigned int am_choice = A_EXTERNID;

static std::unique_ptr<EVP_PKEY, sslfree2>
read_pkey(const unsigned char *pk_str, size_t pk_size)
{
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_PKEY *pk_raw = nullptr;
	std::unique_ptr<OSSL_DECODER_CTX, sslfree2> dec(OSSL_DECODER_CTX_new_for_pkey(&pk_raw,
		"PEM", nullptr, nullptr, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, nullptr, nullptr));
	if (dec == nullptr)
		return nullptr;
	auto ret = OSSL_DECODER_from_data(dec.get(), &pk_str, &pk_size);
	std::unique_ptr<EVP_PKEY, sslfree2> pk_obj(std::move(pk_raw));
	if (ret <= 0)
		return nullptr;
#else
	std::unique_ptr<EVP_PKEY, sslfree2> pk_obj(EVP_PKEY_new());
	if (pk_obj == nullptr)
		return nullptr;
	std::unique_ptr<BIO, sslfree2> bio(BIO_new_mem_buf(pk_str, pk_size));
	if (bio == nullptr)
		return nullptr;
	auto rsa = PEM_read_bio_RSA_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
	if (rsa == nullptr)
		return nullptr;
	EVP_PKEY_assign_RSA(pk_obj.get(), std::move(rsa));
#endif
	return pk_obj;
}

static bool verify_sig(std::unique_ptr<EVP_PKEY, sslfree2> &&pk_obj,
    const std::string_view &plain, std::string &&sig_raw)
{
	std::unique_ptr<EVP_MD_CTX, sslfree> ctx(EVP_MD_CTX_create());

	if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(),
	    nullptr, pk_obj.get()) <= 0)
		return false;
	if (EVP_DigestVerifyUpdate(ctx.get(), plain.data(), plain.size()) <= 0)
		return false;
	return EVP_DigestVerifyFinal(ctx.get(), reinterpret_cast<unsigned char *>(sig_raw.data()),
	       sig_raw.size()) > 0;
}

static bool verify_token(std::string token, std::string &ex_user)
{
	/*
	 * JWTs use unpadded base64url (and they are the only thing to do so in
	 * the scope of Gromox), so just fix it up here rather than decode64_ex.
	 */
	std::replace(token.begin(), token.end(), '-', '+');
	std::replace(token.begin(), token.end(), '_', '/');
	/*
	 * signed_msg := header_b64 "." payload_b64
	 * token := signed_msg "." signature_b64
	 */
	auto beg = token.c_str();
	auto end = strchr(beg, '.');
	if (end == nullptr)
		return false;
	beg = end + 1;
	end = strchr(beg, '.');
	if (end == nullptr)
		return false;
	std::string_view signed_msg(token.c_str(), end - token.c_str());
	std::string payload(beg, end - beg), signature(end + 1);
	payload.insert(payload.size(), (4 - payload.size() % 4) % 4, '=');
	signature.insert(signature.size(), (4 - signature.size() % 4) % 4, '=');

	/* Grab username */
	Json::Value root;
	if (!json_from_str(base64_decode(std::move(payload)), root))
		return false;
	payload.clear();
	ex_user = root["email"].asString();

	/* Load pubkey */
	static constexpr char pk_file[] = PKGSYSCONFDIR "/bearer_pubkey";
	size_t pk_size = 0;
	std::unique_ptr<char[], stdlib_delete> pk_str(HX_slurp_file(pk_file, &pk_size));
	if (pk_str == nullptr) {
		mlog(LV_ERR, "Could not read %s: %s", pk_file, strerror(errno));
		return false;
	}
	auto pkey = read_pkey(reinterpret_cast<const unsigned char *>(pk_str.get()), pk_size);
	if (pkey == nullptr) {
		mlog(LV_ERR, "%s: this does not look like a PEM-encoded RSA key", pk_file);
		return false;
	}
	return time(nullptr) < root["exp"].asInt64() &&
	       verify_sig(std::move(pkey), signed_msg,
	       base64_decode(std::move(signature)));
}

static bool login_token(const char *token,
    unsigned int wantpriv, sql_meta_result &mres) try
{
	std::string ex_user;
	if (!verify_token(token, ex_user)) {
		mres.errstr = "Authentication rejected";
		return false;
	}
	bool auth = true;
	auto err = fptr_mysql_meta(ex_user.c_str(), wantpriv, mres);
	auth = auth && err == 0;
	if (!auth && mres.errstr.empty()) {
		mres.errstr = "Authentication rejected";
		return false;
	}
	return auth;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1701: ENOMEM");
	return false;
}

static bool login_gen(const char *username, const char *password,
    unsigned int wantpriv, sql_meta_result &mres) try
{
	bool auth = false;
	auto err = fptr_mysql_meta(username, wantpriv, mres);
	if (err != 0 || mres.have_xid == 0xFF)
		sleep(1);
	else if (am_choice == A_DENY_ALL)
		auth = false;
	else if (am_choice == A_ALLOW_ALL)
		auth = true;
	else if (am_choice == A_EXTERNID && mres.have_xid > 0)
		auth = fptr_ldap_login(mres.username.c_str(), password, mres);
	else if (am_choice == A_EXTERNID)
		auth = fptr_mysql_login(mres.username.c_str(), password,
		       mres.enc_passwd, mres.errstr);
	auth = auth && err == 0;
	if (!auth && mres.errstr.empty())
		mres.errstr = "Authentication rejected";
	safe_memset(mres.enc_passwd.data(), 0, mres.enc_passwd.size());
	return auth;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1701: ENOMEM");
	return false;
}

static bool authmgr_reload()
{
	auto pfile = config_file_initd("authmgr.cfg", get_config_path(), nullptr);
	if (pfile == nullptr) {
		mlog(LV_ERR, "authmgr: confing_file_initd authmgr.cfg: %s",
		        strerror(errno));
		return false;
	}

	auto val = pfile->get_value("auth_backend_selection");
	if (val == nullptr) {
	} else if (strcmp(val, "deny_all") == 0) {
		am_choice = A_DENY_ALL;
		mlog(LV_NOTICE, "authmgr: All authentication requests will be denied");
	} else if (strcmp(val, "allow_all") == 0) {
		am_choice = A_ALLOW_ALL;
		mlog(LV_NOTICE, "authmgr: Arbitrary passwords will be accepted for authentication");
	} else if (strcmp(val, "always_mysql") == 0 || strcmp(val, "always_ldap") == 0) {
		am_choice = A_EXTERNID;
		mlog(LV_WARN, "authmgr: auth_backend_selection=always_mysql/always_ldap is obsolete; switching to =externid");
	} else if (strcmp(val, "externid") == 0) {
		am_choice = A_EXTERNID;
	}

	if (fptr_ldap_login == nullptr) {
		query_service2("ldap_auth_login3", fptr_ldap_login);
		if (fptr_ldap_login == nullptr) {
			mlog(LV_ERR, "authmgr: ldap_adaptor plugin not loaded yet");
			return false;
		}
	}
	return true;
}

static bool authmgr_init()
{
	if (!authmgr_reload())
		return false;
	query_service2("mysql_auth_meta", fptr_mysql_meta);
	query_service2("mysql_auth_login2", fptr_mysql_login);
	if (fptr_mysql_meta == nullptr ||
	    fptr_mysql_login == nullptr) {
		mlog(LV_ERR, "authmgr: mysql_adaptor plugin not loaded yet");
		return false;
	}
	if (!register_service("auth_login_gen", login_gen)) {
		mlog(LV_ERR, "authmgr: failed to register auth services");
		return false;
	}
	if (!register_service("auth_login_token", login_token)) {
		mlog(LV_ERR, "authmgr: failed to register auth services");
		return false;
	}
	return true;
}

static BOOL svc_authmgr(int reason, void **datap) try
{
	if (reason == PLUGIN_RELOAD) {
		authmgr_reload();
		return TRUE;
	}
	if (reason != PLUGIN_INIT)
		return TRUE;
	LINK_SVC_API(datap);
	return authmgr_init() ? TRUE : false;
} catch (...) {
	return false;
}
SVC_ENTRY(svc_authmgr);
