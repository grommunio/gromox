// SPDX-License-Identifier: GPL-3.0-or-later
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iconv.h>
#include <memory>
#include <mutex>
#include <libHX/string.h>
#include <openssl/evp.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <gromox/arcfour.hpp>
#include <gromox/crc32.hpp>
#include <gromox/cryptoutil.hpp>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/ndr.hpp>
#include <gromox/ntlmssp.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>

#define MSVAVEOL					0
#define MSVAVNBCOMPUTERNAME			1
#define MSVAVNBDOMAINNAME			2
#define MSVAVDNSCOMPUTERNAME		3
#define MSVAVDNSDOMAINNAME			4


#define NTLMSSP_SIG_SIZE			16

#define NTLMSSP_SIGN_VERSION		0x01

#define NTLMSSP_DIRECTION_SEND		0
#define NTLMSSP_DIRECTION_RECEIVE	1

#define CLI_SIGN		"session key to client-to-server signing key magic constant"
#define CLI_SEAL		"session key to client-to-server sealing key magic constant"
#define SRV_SIGN		"session key to server-to-client signing key magic constant"
#define SRV_SEAL		"session key to server-to-client sealing key magic constant"

using namespace gromox;

enum {
	NTLMSSP_WINDOWS_MAJOR_VERSION_5 = 0x05,
	NTLMSSP_WINDOWS_MAJOR_VERSION_6 = 0x06,
	NTLMSSP_WINDOWS_MINOR_VERSION_0 = 0x00,
	NTLMSSP_WINDOWS_MINOR_VERSION_1 = 0x01,
	NTLMSSP_WINDOWS_MINOR_VERSION_2 = 0x02,
	NTLMSSP_REVISION_W2K3_RC10x0A = 0x0A,
	NTLMSSP_REVISION_W2K3 = 0x0F,
};

namespace {

struct NTLM_AUTH_CHALLENGE {
	DATA_BLOB blob;
	uint8_t blob_buff[8]; /* buffer for DATA_BLOB's data */
};

struct NTLMSSP_CRYPT_DIRECTION {
	uint32_t seq_num;
	uint8_t sign_key[16];
	ARCFOUR_STATE seal_state;
};

struct NTLMSSP_CRYPT_DIRECTION_V2 {
	NTLMSSP_CRYPT_DIRECTION sending;
	NTLMSSP_CRYPT_DIRECTION receiving;
};

union NTLMSSP_CRYPT_STATE {
	NTLMSSP_CRYPT_DIRECTION ntlm;     /* NTLM */
	NTLMSSP_CRYPT_DIRECTION_V2 ntlm2; /* NTLM2 */
};

}

struct NTLMSSP_CTX {
	std::mutex lock;
	uint32_t expected_state = NTLMSSP_PROCESS_NEGOTIATE;
	bool unicode = false;
	bool allow_lm_key = false; /* The LM_KEY code is not very secure... */
	char user[128]{}, domain[128]{};
	uint8_t *nt_hash = nullptr, *lm_hash = nullptr;
	char netbios_name[128]{}, dns_name[128]{}, dns_domain[128]{};
	DATA_BLOB internal_chal{}; /* Random challenge as supplied to the client for NTLM authentication */
	uint8_t internal_chal_buff[32]{};
	DATA_BLOB lm_resp{}, nt_resp{}, session_key{};
	uint8_t lm_resp_buff[32]{}, nt_resp_buff[512]{}, session_key_buff[32];
	uint32_t neg_flags = /* the current state of negotiation with the NTLMSSP partner */
		NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_VERSION |
		NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL;
	NTLMSSP_CRYPT_STATE crypt{};
	NTLM_AUTH_CHALLENGE challenge{};
	NTLMSSP_GET_PASSWORD get_password = nullptr;
};

namespace {

struct NTLMSSP_SERVER_AUTH_STATE {
	DATA_BLOB user_session_key;
	uint8_t user_session_key_buff[32];
	DATA_BLOB lm_session_key;
	uint8_t lm_session_key_buff[32];
	DATA_BLOB encrypted_session_key; /* internal variables used by KEY_EXCH */
	uint8_t encrypted_session_key_buff[32];
	bool doing_ntlm2;
	uint8_t session_nonce[16]; /* internal variables used by NTLM2 */
};

struct NTLMSSP_VERSION {
	uint8_t major_vers;
	uint8_t minor_vers;
	uint16_t product_build;
	uint8_t reserved[3];
	uint8_t ntlm_revers;
};

}

static void str_to_key(const uint8_t *s, uint8_t *k)
{
	k[0] = s[0] >> 1;
	k[1] = ((s[0] & 0x01) << 6) | (s[1] >> 2);
	k[2] = ((s[1] & 0x03) << 5) | (s[2] >> 3);
	k[3] = ((s[2] & 0x07) << 4) | (s[3] >> 4);
	k[4] = ((s[3] & 0x0F) << 3) | (s[4] >> 5);
	k[5] = ((s[4] & 0x1F) << 2) | (s[5] >> 6);
	k[6] = ((s[5] & 0x3F) << 1) | (s[6] >> 7);
	k[7] = s[6] & 0x7F;
	for (size_t i = 0; i < 8; ++i)
		k[i] <<= 1;
}

static bool des_crypt56(uint8_t out[8], const uint8_t in[8], const uint8_t key[7])
{
	uint8_t dummy_pad[8];
	int dummy_n;
	auto cipher = EVP_get_cipherbynid(NID_des_ecb);
	if (cipher == nullptr)
		return false;
	std::unique_ptr<EVP_CIPHER_CTX, sslfree> ctx(EVP_CIPHER_CTX_new());
	if (ctx == nullptr)
		return false;
	if (EVP_CIPHER_CTX_set_padding(ctx.get(), 0) <= 0)
		return false;
	static constexpr uint8_t iv[16]{};
	uint8_t derived_key[8];
	str_to_key(key, derived_key);
	if (EVP_CipherInit_ex(ctx.get(), cipher, nullptr, derived_key, iv, 1) <= 0 ||
	    EVP_CipherUpdate(ctx.get(), out, &dummy_n, in, 8) <= 0 ||
	    EVP_CipherFinal_ex(ctx.get(), dummy_pad, &dummy_n) <= 0)
		return false;
	return true;
}

static bool E_P16(const uint8_t *p14, uint8_t *p16)
{
	static constexpr uint8_t sp8[] = {0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25}; // KGS!@#$%
	return des_crypt56(p16, sp8, p14) && des_crypt56(p16 + 8, sp8, p14 + 7);
}

static bool E_P24(const uint8_t *p21, const uint8_t *c8, uint8_t *p24)
{
	return des_crypt56(p24, c8, p21) && des_crypt56(p24 + 8, c8, p21 + 7) &&
	       des_crypt56(p24 + 16, c8, p21 + 14);
}

static bool ntlmssp_lm_session_key(const uint8_t lm_hash[16],
	const uint8_t lm_resp[24], uint8_t session_key[16])
{
	/* calculate the LM session key (effective length 40 bits,
	   but changes with each session) */
	uint8_t partial_lm_hash[14];

	
	memcpy(partial_lm_hash, lm_hash, 8);
	memset(partial_lm_hash + 8, 0xbd, 6);
	return des_crypt56(session_key, lm_resp, partial_lm_hash) &&
	       des_crypt56(session_key + 8, lm_resp, partial_lm_hash + 7);
}

static bool ntlmssp_calc_ntlm2_key(uint8_t subkey[MD5_DIGEST_LENGTH],
	DATA_BLOB session_key, const char *constant)
{
	std::unique_ptr<EVP_MD_CTX, sslfree> ctx(EVP_MD_CTX_new());
	if (ctx == nullptr ||
	    EVP_DigestInit(ctx.get(), EVP_md5()) <= 0)
		return false;
	if (EVP_DigestUpdate(ctx.get(), session_key.data, session_key.length) <= 0 ||
	    EVP_DigestUpdate(ctx.get(), constant, strlen(constant) + 1) <= 0 ||
	    EVP_DigestFinal(ctx.get(), subkey, nullptr) <= 0)
		return false;
	return true;
}

static int ntlmssp_utf8_to_utf16le(const char *src, void *dst, size_t len)
{
	size_t in_len;
	size_t out_len;
	iconv_t conv_id;

	conv_id = iconv_open("UTF-16LE", "UTF-8");
	if (conv_id == (iconv_t)-1)
		return -1;
	auto pin  = deconst(src);
	auto pout = static_cast<char *>(dst);
	in_len = strlen(src);
	memset(dst, 0, len);
	out_len = len;
	if (iconv(conv_id, &pin, &in_len, &pout, &len) == static_cast<size_t>(-1)) {
		iconv_close(conv_id);
		return -1;
	} else {
		iconv_close(conv_id);
		return out_len - len;
	}
}

static bool ntlmssp_utf16le_to_utf8(const void *src, size_t src_len,
	char *dst, size_t len)
{
	char *pin, *pout;
	iconv_t conv_id;

	conv_id = iconv_open("UTF-8", "UTF-16LE");
	if (conv_id == (iconv_t)-1)
		return false;
	pin = (char*)src;
	pout = dst;
	memset(dst, 0, len);
	if (iconv(conv_id, &pin, &src_len, &pout, &len) == static_cast<size_t>(-1)) {
		iconv_close(conv_id);
		return false;
	} else {
		iconv_close(conv_id);
		return true;
	}
}

static bool ntlmssp_md4hash(const char *passwd, void *p16v)
{
	auto p16 = static_cast<uint8_t *>(p16v);
	int passwd_len;
	char upasswd[256];

	memset(p16, 0, MD4_DIGEST_LENGTH);
	passwd_len = ntlmssp_utf8_to_utf16le(passwd, upasswd, sizeof(upasswd));
	if (passwd_len < 0) {
		return false;
	}
	std::unique_ptr<EVP_MD_CTX, sslfree> ctx(EVP_MD_CTX_new());
	if (ctx == nullptr ||
	    EVP_DigestInit(ctx.get(), EVP_md4()) <= 0 ||
	    EVP_DigestUpdate(ctx.get(), upasswd, passwd_len) <= 0 ||
	    EVP_DigestFinal(ctx.get(), p16, nullptr) <= 0)
		return false;
	return true;
}

static bool ntlmssp_deshash(const char *passwd, uint8_t p16[16])
{
	int len;
	char tmpbuf[14];
	
	if (strlen(passwd) >= sizeof(tmpbuf)) {
		len = sizeof(tmpbuf) - 1;
		memcpy(tmpbuf, passwd, len);
		tmpbuf[len] = '\0';
	} else {
		strcpy(tmpbuf, passwd);
	}
	HX_strupper(tmpbuf);
	/* Only the first 14 chars are considered */
	return E_P16(reinterpret_cast<uint8_t *>(tmpbuf), p16);
}

/*
  format specifiers are:

  U = unicode string (input is utf-8 string)
  a = address (input is char *ascii_string)
      (1 byte type, 1 byte length, unicode/ASCII string, all inline)
  A = ASCII string (input is ascii string)
  B = data blob (pointer + length)
  b = data blob in header (pointer + length)
  d = word (4 bytes)
  C = constant ascii string
 */
static bool ntlmssp_gen_packet(DATA_BLOB *pblob, const char *format, ...)
{
	
	char *s;
	int i, j;
	uint8_t *b;
	va_list ap, aq;
	uint32_t length;
	int intargs[64];
	uint8_t buffs[64][1024];
	DATA_BLOB blobs[64];
	int head_ofs, data_ofs;
	int head_size, data_size;
	
	
	if (strlen(format) > sizeof(blobs) / sizeof(DATA_BLOB)) {
		return false;
	}
	
	memset(blobs, 0, sizeof(blobs));
	head_size = 0;
	data_size = 0;
	/* first scan the format to work out the header and body size */
	va_start(ap, format);
	va_copy(aq, ap);
	auto cl_0 = make_scope_exit([&]() {
		va_end(aq);
		va_end(ap);
	});
	for (i=0; format[i]; i++) {
		switch (format[i]) {
		case 'U': {
			s = va_arg(ap, char*);
			head_size += 8;
			auto ret = ntlmssp_utf8_to_utf16le(s, buffs[i], arsizeof(buffs[i]));
			if (ret < 0) {
				return false;
			}
			blobs[i].length = ret;
			blobs[i].data = buffs[i];
			data_size += blobs[i].length;
			break;
		}
		case 'A':
			s = va_arg(ap, char*);
			head_size += 8;
			blobs[i].cdata = s;
			blobs[i].length = strlen(s);
			data_size += blobs[i].length;
			break;
		case 'a': {
			j = va_arg(ap, int);
			intargs[i] = j;
			s = va_arg(ap, char*);
			auto ret = ntlmssp_utf8_to_utf16le(s, buffs[i], arsizeof(buffs[i]));
			if (ret < 0) {
				return false;
			}
			blobs[i].length = ret;
			blobs[i].data = buffs[i];
			data_size += blobs[i].length + 4;
			break;
		}
		case 'B':
			b = va_arg(ap, uint8_t*);
			head_size += 8;
			blobs[i].data = b;
			blobs[i].length = va_arg(ap, int);
			data_size += blobs[i].length;
			break;
		case 'b':
			b = va_arg(ap, uint8_t*);
			blobs[i].data = b;
			blobs[i].length = va_arg(ap, int);
			head_size += blobs[i].length;
			break;
		case 'd':
			j = va_arg(ap, int);
			intargs[i] = j;
			head_size += 4;
			break;
		case 'C':
			s = va_arg(ap, char*);
			blobs[i].data = (uint8_t*)s;
			blobs[i].length = strlen(s) + 1;
			head_size += blobs[i].length;
			break;
		default:
			return false;
		}
	}

	if (head_size + data_size == 0) {
		return false;
	}
	
	head_ofs = 0;
	data_ofs = head_size;

	for (i=0; format[i]; i++) {
		switch (format[i]) {
		case 'U':
		case 'A':
		case 'B':
			length = blobs[i].length;
			cpu_to_le16p(&pblob->data[head_ofs], length);
			head_ofs += 2;
			cpu_to_le16p(&pblob->data[head_ofs], length);
			head_ofs += 2;
			cpu_to_le32p(&pblob->data[head_ofs], data_ofs);
			head_ofs += 4;
			if (NULL != blobs[i].data && length > 0) {
				/* don't follow null blobs... */
				memcpy(pblob->data + data_ofs, blobs[i].data, length);
			}
			data_ofs += length;
			break;
		case 'a':
			cpu_to_le16p(&pblob->data[data_ofs], intargs[i]);
			data_ofs += 2;
			length = blobs[i].length;
			cpu_to_le16p(&pblob->data[data_ofs], length);
			data_ofs += 2;
			memcpy(pblob->data + data_ofs, blobs[i].data, length);
			data_ofs += length;
			break;
		case 'd':
			cpu_to_le32p(&pblob->data[head_ofs], intargs[i]);
			head_ofs += 4;
			break;
		case 'b':
			length = blobs[i].length;
			if (NULL != blobs[i].data && length > 0) {
				/* don't follow null blobs... */
				memcpy(pblob->data + head_ofs, blobs[i].data, length);
			}
			head_ofs += length;
			break;
		case 'C':
			length = blobs[i].length;
			memcpy(pblob->data + head_ofs, blobs[i].data, length);
			head_ofs += length;
			break;
		default:
			return false;
		}
	}
	pblob->length = head_size + data_size;
	return true;
}

/*
  format specifiers are:

  U = unicode string (output is utf8, input first 4 bytes for buffer length)
  A = ascii string
  B = data blob (input blob.length of buffer length)
  b = data blob in header (input blob.length of buffer length)
  d = word (4 bytes)
  C = constant ascii string
 */
static bool ntlmssp_parse_packet(const DATA_BLOB blob, const char *format, ...)
{
	int i;
	char *ps;
	va_list ap;
	uint32_t *v;
	size_t head_ofs;
	uint32_t ptr_ofs;
	DATA_BLOB *pblob;
	uint16_t len1, len2;
	
	
	head_ofs = 0;
	va_start(ap, format);
	for (i=0; format[i]; i++) {
		switch (format[i]) {
		case 'U':
			if (head_ofs + 8 > blob.length) {
				va_end(ap);
				return false;
			}
			len1 = le16p_to_cpu(&blob.data[head_ofs]);
			head_ofs += 2;
			len2 = le16p_to_cpu(&blob.data[head_ofs]);
			head_ofs += 2;
			ptr_ofs = le32p_to_cpu(&blob.data[head_ofs]);
			head_ofs += 4;

			ps = va_arg(ap, char*);
			if (0 == len1 && 0 == len2) {
				ps[0] = '\0';
				break;
			}
			/* make sure its in the right format - be strict */
			if (len1 != len2 || ptr_ofs + len1 < ptr_ofs ||
				ptr_ofs + len1 < len1 || ptr_ofs + len1 > blob.length) {
				va_end(ap);
				return false;
			}
			if (len1 & 1) {
				/* if odd length and unicode */
				va_end(ap);
				return false;
			}
			if (blob.data + ptr_ofs < (uint8_t*)(long)ptr_ofs ||
				blob.data + ptr_ofs < blob.data) {
				va_end(ap);
				return false;
			}
			if (len1 > 0) {
				if (!ntlmssp_utf16le_to_utf8(blob.data + ptr_ofs,
				    len1, ps, le32p_to_cpu(ps))) {
					va_end(ap);
					return false;
				}
			} else {
				ps[0] = '\0';
			}
			break;
		case 'A':
			if (head_ofs + 8 > blob.length) {
				va_end(ap);
				return false;
			}
			len1 = le16p_to_cpu(&blob.data[head_ofs]);
			head_ofs += 2;
			len2 = le16p_to_cpu(&blob.data[head_ofs]);
			head_ofs += 2;
			ptr_ofs = le32p_to_cpu(&blob.data[head_ofs]);
			head_ofs += 4;

			ps = va_arg(ap, char*);
			/* make sure its in the right format - be strict */
			if (0 == len1 && 0 == len2) {
				ps[0] = '\0';
				break;
			}
			if (len1 != len2 || ptr_ofs + len1 < ptr_ofs ||
				ptr_ofs + len1 < len1 || ptr_ofs + len1 > blob.length) {
				va_end(ap);
				return false;
			}
			if (blob.data + ptr_ofs < (uint8_t *)(long)ptr_ofs ||
				blob.data + ptr_ofs < blob.data) {
				va_end(ap);
				return false;
			}
			if (len1 > 0) {
				memcpy(ps, blob.data + ptr_ofs, len1);
				ps[len1] = '\0';
			} else {
				ps[0] = '\0';
			}
			break;
		case 'B':
			if (head_ofs + 8 > blob.length) {
				va_end(ap);
				return false;
			}
			len1 = le16p_to_cpu(&blob.data[head_ofs]);
			head_ofs += 2;
			len2 = le16p_to_cpu(&blob.data[head_ofs]);
			head_ofs += 2;
			ptr_ofs = le32p_to_cpu(&blob.data[head_ofs]);
			head_ofs += 4;

			pblob = (DATA_BLOB*)va_arg(ap, void*);
			if (0 == len1 && 0 == len2) {
				pblob->length = 0;
			} else {
				/* make sure its in the right format - be strict */
				if (len1 != len2 || ptr_ofs + len1 < ptr_ofs ||
					ptr_ofs + len1 < len1 || ptr_ofs + len1 > blob.length) {
					va_end(ap);
					return false;
				}

				if (blob.data + ptr_ofs < (uint8_t*)(long)ptr_ofs ||
					blob.data + ptr_ofs < blob.data || pblob->length < len1) {
					va_end(ap);
					return false;
				}
				
				memcpy(pblob->data, blob.data + ptr_ofs, len1);
				pblob->length = len1;
			}
			break;
		case 'b':
			pblob = (DATA_BLOB *)va_arg(ap, void*);
			len1 = va_arg(ap, unsigned int);
			/* make sure its in the right format - be strict */
			if (head_ofs + len1 > blob.length) {
				va_end(ap);
				return false;
			}
			if (blob.data + head_ofs < (uint8_t *)head_ofs ||
				blob.data + head_ofs < blob.data || pblob->length < len1) {
				va_end(ap);
				return false;
			}
			memcpy(pblob->data, blob.data + head_ofs, len1);
			pblob->length = len1;
			head_ofs += len1;
			break;
		case 'd':
			v = va_arg(ap, uint32_t*);
			if (head_ofs + 4 > blob.length) {
				va_end(ap);
				return false;
			}
			*v = le32p_to_cpu(&blob.data[head_ofs]);
			head_ofs += 4;
			break;
		case 'C':
			ps = va_arg(ap, char*);

			if (blob.data + head_ofs < (uint8_t *)head_ofs ||
				blob.data + head_ofs < blob.data ||
			    head_ofs + strlen(ps) + 1 > blob.length) {
				va_end(ap);
				return false;
			}

			if (0 != memcmp(blob.data + head_ofs, ps, strlen(ps) + 1)) {
				va_end(ap);
				return false;
			}
			head_ofs += strlen(ps) + 1;
			break;
		}
	}
	
	va_end(ap);
	return true;
}


/* neg_flags can be one ore more following
	NTLMSSP_NEGOTIATE_128
	NTLMSSP_NEGOTIATE_56
	NTLMSSP_NEGOTIATE_KEY_EXCH
	NTLMSSP_NEGOTIATE_ALWAYS_SIGN
	NTLMSSP_NEGOTIATE_NTLM2
*/
NTLMSSP_CTX *ntlmssp_init(const char *netbios_name, const char *dns_name,
    const char *dns_domain, bool allow_lm_key, uint32_t neg_flags,
    NTLMSSP_GET_PASSWORD get_password) try
{
	auto pntlmssp = new NTLMSSP_CTX;
	pntlmssp->allow_lm_key = allow_lm_key;
	pntlmssp->neg_flags |= neg_flags;
	gx_strlcpy(pntlmssp->netbios_name, netbios_name, GX_ARRAY_SIZE(pntlmssp->netbios_name));
	gx_strlcpy(pntlmssp->dns_name, dns_name, GX_ARRAY_SIZE(pntlmssp->dns_name));
	gx_strlcpy(pntlmssp->dns_domain, dns_domain, GX_ARRAY_SIZE(pntlmssp->dns_domain));
	pntlmssp->get_password = get_password;
	return pntlmssp;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1645: ENOMEM\n");
	return nullptr;
}

static void ntlmssp_handle_neg_flags(NTLMSSP_CTX *pntlmssp, uint32_t neg_flags)
{
	if (neg_flags & NTLMSSP_NEGOTIATE_UNICODE) {
		pntlmssp->neg_flags |= NTLMSSP_NEGOTIATE_UNICODE;
		pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_OEM;
		pntlmssp->unicode = true;
	} else {
		pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_UNICODE;
		pntlmssp->neg_flags |= NTLMSSP_NEGOTIATE_OEM;
		pntlmssp->unicode = false;
	}

	if (neg_flags & NTLMSSP_NEGOTIATE_LM_KEY && pntlmssp->allow_lm_key)
		/* other end forcing us to use LM */
		pntlmssp->neg_flags |= NTLMSSP_NEGOTIATE_LM_KEY;
	else
		pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;

	if (!(neg_flags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN))
		pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
	if (!(neg_flags & NTLMSSP_NEGOTIATE_NTLM2))
		pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_NTLM2;
	if (!(neg_flags & NTLMSSP_NEGOTIATE_128))
		pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_128;
	if (!(neg_flags & NTLMSSP_NEGOTIATE_56))
		pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_56;
	if (!(neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH))
		pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_KEY_EXCH;
	if (!(neg_flags & NTLMSSP_NEGOTIATE_SIGN))
		pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_SIGN;
	if (!(neg_flags & NTLMSSP_NEGOTIATE_SEAL))
		pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_SEAL;
	if (!(neg_flags & NTLMSSP_NEGOTIATE_VERSION))
		pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_VERSION;
	if (neg_flags & NTLMSSP_REQUEST_TARGET) {
		pntlmssp->neg_flags |= NTLMSSP_REQUEST_TARGET;
	}
}


static const char *ntlmssp_target_name(NTLMSSP_CTX *pntlmssp,
	uint32_t neg_flags, uint32_t *chal_flags)
{
	if (neg_flags & NTLMSSP_REQUEST_TARGET) {
		*chal_flags |= NTLMSSP_NEGOTIATE_TARGET_INFO;
		*chal_flags |= NTLMSSP_REQUEST_TARGET;
		*chal_flags |= NTLMSSP_TARGET_TYPE_SERVER;
		return pntlmssp->dns_name;
	} else {
		return "";
	}
}

static int ntlmssp_ndr_push_ntlm_version(NDR_PUSH *pndr, NTLMSSP_VERSION *r)
{
	int status;
	
	status = ndr_push_align(pndr, 2);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, r->major_vers);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, r->minor_vers);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->product_build);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_array_uint8(pndr, r->reserved, 3);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, r->ntlm_revers);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_trailer_align(pndr, 2);
}

static bool ntlmssp_server_negotiate(NTLMSSP_CTX *pntlmssp,
	const DATA_BLOB request, DATA_BLOB *preply)
{
	NDR_PUSH ndr_push;
	uint32_t neg_flags;
	uint32_t chal_flags;
	char ndr_buff[1024];
	NTLMSSP_VERSION vers;
	DATA_BLOB struct_blob;
	DATA_BLOB version_blob;
	char cryptkey[9];
	const char *target_name;
	const char *parse_string;
	uint32_t ntlmssp_command;
	uint8_t struct_blob_buff[1024];
	
	neg_flags = 0;
	if (0 != request.length) {
		if (request.length < 16 || !ntlmssp_parse_packet(request,
		    "Cdd", "NTLMSSP", &ntlmssp_command, &neg_flags))
			return false;
	}

	ntlmssp_handle_neg_flags(pntlmssp, neg_flags);
	if (pntlmssp->challenge.blob.length > 0) {
		/* get the previous challenge */
		memcpy(cryptkey, pntlmssp->challenge.blob.data, 8);
	} else {
		/* produce cryptkey and copy it to challenge */
		randstring(cryptkey, 8);
		pntlmssp->challenge.blob.data = pntlmssp->challenge.blob_buff;
		memcpy(pntlmssp->challenge.blob_buff, cryptkey, 8);
		pntlmssp->challenge.blob.length = 8;
	}
	
	
	/* The flags we send back are not just the negotiated flags,
	 * they are also 'what is in this packet'.  Therefore, we
	 * operate on 'chal_flags' from here on
	 */

	chal_flags = pntlmssp->neg_flags;

	/* get the right name to fill in as 'target' */
	target_name = ntlmssp_target_name(pntlmssp, neg_flags, &chal_flags);

	pntlmssp->internal_chal.data = pntlmssp->internal_chal_buff;
	memcpy(pntlmssp->internal_chal.data, cryptkey, 8);
	pntlmssp->internal_chal.length = 8;
	
	struct_blob.data = struct_blob_buff;
	struct_blob.length = 0;
	if (chal_flags & NTLMSSP_NEGOTIATE_TARGET_INFO) {
		if (!ntlmssp_gen_packet(&struct_blob, "aaaaa",
		    MSVAVNBDOMAINNAME, target_name,
		    MSVAVNBCOMPUTERNAME, pntlmssp->netbios_name,
		    MSVAVDNSDOMAINNAME, pntlmssp->dns_domain,
		    MSVAVDNSCOMPUTERNAME, pntlmssp->dns_name,
		    MSVAVEOL, ""))
			return false;
	} else {
		struct_blob.data = NULL;
		struct_blob.length = 0;
	}

	
	/* Marshal the packet in the right format, unicode or ASCII */
	
	version_blob.data = NULL;
	version_blob.length = 0;
	
	if (chal_flags & NTLMSSP_NEGOTIATE_VERSION) {
		memset(&vers, 0, sizeof(NTLMSSP_VERSION));
		vers.major_vers = NTLMSSP_WINDOWS_MAJOR_VERSION_6;
		vers.minor_vers = NTLMSSP_WINDOWS_MINOR_VERSION_1;
		vers.product_build = 0;
		vers.ntlm_revers = NTLMSSP_REVISION_W2K3;
		
		ndr_push_init(&ndr_push, ndr_buff, sizeof(ndr_buff), 0);
		
		if (NDR_ERR_SUCCESS != ntlmssp_ndr_push_ntlm_version(&ndr_push,
			&vers)) {
			return false;
		}
		
		version_blob.data = ndr_push.data;
		version_blob.length = ndr_push.offset;
	}
		
	if (pntlmssp->unicode)
		parse_string = "CdUdbddBb";
	else
		parse_string = "CdAdbddBb";
	if (!ntlmssp_gen_packet(preply, parse_string, "NTLMSSP",
	    NTLMSSP_PROCESS_CHALLENGE, target_name, chal_flags, cryptkey,
	    8, 0, 0, struct_blob.data, struct_blob.length, version_blob.data,
	    version_blob.length))
		return false;
	
	pntlmssp->expected_state = NTLMSSP_PROCESS_AUTH;
	return true;
}

static bool ntlmssp_server_preauth(NTLMSSP_CTX *pntlmssp,
	NTLMSSP_SERVER_AUTH_STATE *pauth, const DATA_BLOB request)
{
	const char *parse_string;
	char client_netbios_name[1024];
	uint8_t session_nonce_hash[16];
	uint32_t ntlmssp_command, auth_flags;
	
	if (pntlmssp->unicode)
		parse_string = "CdBBUUUBd";
	else
		parse_string = "CdBBAAABd";

	pntlmssp->session_key.data = pntlmssp->session_key_buff;
	pntlmssp->session_key.length = 0;
	
	pntlmssp->lm_resp.data = pntlmssp->lm_resp_buff;
	pntlmssp->lm_resp.length = sizeof(pntlmssp->lm_resp_buff);
	
	pntlmssp->nt_resp.data = pntlmssp->nt_resp_buff;
	pntlmssp->nt_resp.length = sizeof(pntlmssp->nt_resp_buff);
	
	pntlmssp->user[0] = '\0';
	pntlmssp->domain[0] = '\0';
	
	pauth->encrypted_session_key.data = pauth->encrypted_session_key_buff;
	pauth->encrypted_session_key.length =
							sizeof(pauth->encrypted_session_key_buff);
	cpu_to_le32p(pntlmssp->domain, sizeof(pntlmssp->domain));
	cpu_to_le32p(pntlmssp->user, sizeof(pntlmssp->user));
	cpu_to_le32p(client_netbios_name, sizeof(client_netbios_name));

	/* now the NTLMSSP encoded auth hashes */
	if (!ntlmssp_parse_packet(request, parse_string, "NTLMSSP",
	    &ntlmssp_command, &pntlmssp->lm_resp, &pntlmssp->nt_resp,
	    pntlmssp->domain, pntlmssp->user, client_netbios_name,
	    &pauth->encrypted_session_key, &auth_flags)) {
		/* Try again with a shorter string (Win9X truncates this packet) */
		if (pntlmssp->unicode)
			parse_string = "CdBBUUU";
		else
			parse_string = "CdBBAAA";
		pauth->encrypted_session_key.length = 0;
		auth_flags = 0;
		
		cpu_to_le32p(pntlmssp->domain, sizeof(pntlmssp->domain));
		cpu_to_le32p(pntlmssp->user, sizeof(pntlmssp->user));
		cpu_to_le32p(client_netbios_name, sizeof(client_netbios_name));
		pntlmssp->lm_resp.length = sizeof(pntlmssp->lm_resp_buff);
		pntlmssp->nt_resp.length = sizeof(pntlmssp->nt_resp_buff);
		/* now the NTLMSSP encoded auth hashes */
		if (!ntlmssp_parse_packet(request, parse_string, "NTLMSSP",
		    &ntlmssp_command, &pntlmssp->lm_resp, &pntlmssp->nt_resp,
		    pntlmssp->domain, pntlmssp->user, client_netbios_name))
			return false;
	}

	if (0 != auth_flags) {
		ntlmssp_handle_neg_flags(pntlmssp, auth_flags);
	}
	
	if (!(pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) ||
	    pntlmssp->nt_resp.length != 24 || pntlmssp->lm_resp.length != 24)
		return true;
	pauth->doing_ntlm2 = true;
	memcpy(pauth->session_nonce, pntlmssp->internal_chal.data, 8);
	memcpy(pauth->session_nonce + 8, pntlmssp->lm_resp.data, 8);

	std::unique_ptr<EVP_MD_CTX, sslfree> ctx(EVP_MD_CTX_new());
	if (ctx == nullptr ||
	    EVP_DigestInit(ctx.get(), EVP_md5()) <= 0 ||
	    EVP_DigestUpdate(ctx.get(), pauth->session_nonce, 16) <= 0 ||
	    EVP_DigestFinal(ctx.get(), session_nonce_hash, nullptr) <= 0)
		return false;

	/* LM response is no longer useful */
	pntlmssp->lm_resp.length = 0;

	memcpy(pntlmssp->challenge.blob.data, session_nonce_hash, 8);
	pntlmssp->challenge.blob.length = 8;

	/* LM Key is incompatible. */
	pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
	return true;
}

static bool ntlmssp_check_ntlm1(const DATA_BLOB *pnt_response,
	const uint8_t *part_passwd, const DATA_BLOB *psec_blob,
	DATA_BLOB *puser_key)
{
	/* Finish the encryption of part_passwd. */
	uint8_t p21[21];
	uint8_t p24[24];
	
	if (psec_blob->length != 8) {
		debug_info("[ntlmssp]: incorrect challenge size (%lu) in check_ntlm1", 
			(unsigned long)psec_blob->length);
		return false;
	}

	if (pnt_response->length != 24) {
		debug_info("[ntlmssp]: incorrect password length (%lu) in check_ntlm1", 
			(unsigned long)pnt_response->length);
		return false;
	}

	memset(p21, 0, sizeof(p21));
	memcpy(p21, part_passwd, 16);
	if (!E_P24(p21, psec_blob->data, p24))
		return false;
	
	if (memcmp(p24, pnt_response->data, 24) != 0)
		return false;
	if (puser_key == nullptr)
		return true;
	std::unique_ptr<EVP_MD_CTX, sslfree> ctx(EVP_MD_CTX_new());
	if (ctx == nullptr ||
	    EVP_DigestInit(ctx.get(), EVP_md4()) <= 0 ||
	    EVP_DigestUpdate(ctx.get(), part_passwd, 16) <= 0 ||
	    EVP_DigestFinal(ctx.get(), puser_key->data, nullptr) <= 0)
		return false;
	puser_key->length = 16;
	return true;
}

static bool ntlmssp_check_ntlm2(const DATA_BLOB *pntv2_response,
	const uint8_t *part_passwd, const DATA_BLOB *psec_blob,
	const char *user, const char *domain, DATA_BLOB *puser_key)
{
	int user_len;
	int domain_len;
	uint8_t kr[16]; /* Finish the encryption of part_passwd. */
	char user_in[256];
	char tmp_user[UADDR_SIZE];
	char domain_in[256];
	DATA_BLOB client_key;
	uint8_t value_from_encryption[16];

	if (psec_blob->length != 8) {
		debug_info("[ntlmssp]: incorrect challenge size (%u) "
			"in check_ntlm2", psec_blob->length);
		return false;
	}

	if (pntv2_response->length < 24) {
		debug_info("[ntlmssp]: incorrect password length (%u) "
			"in check_ntlm2", pntv2_response->length);
		return false;
	}

	client_key.data = pntv2_response->data + 16;
	client_key.length = pntv2_response->length - 16;
	gx_strlcpy(tmp_user, user, GX_ARRAY_SIZE(tmp_user));
	HX_strupper(tmp_user);
	user_len = ntlmssp_utf8_to_utf16le(tmp_user, user_in, sizeof(user_in));
	domain_len = ntlmssp_utf8_to_utf16le(domain, domain_in, sizeof(domain_in));
	if (user_len < 0 || domain_len < 0) {
		return false;
	}

	HMACMD5_CTX hmac_ctx(part_passwd, 16);
	if (!hmac_ctx.is_valid() ||
	    !hmac_ctx.update(user_in, user_len) ||
	    !hmac_ctx.update(domain_in, domain_len) ||
	    !hmac_ctx.finish(kr))
		return false;

	hmac_ctx = HMACMD5_CTX(kr, 16);
	if (!hmac_ctx.is_valid() ||
	    !hmac_ctx.update(psec_blob->data, psec_blob->length) ||
	    !hmac_ctx.update(client_key.data, client_key.length) ||
	    !hmac_ctx.finish(value_from_encryption))
		return false;

	if (0 == memcmp(value_from_encryption, pntv2_response->data, 16)) {
		hmac_ctx = HMACMD5_CTX(kr, 16);
		if (!hmac_ctx.is_valid() ||
		    !hmac_ctx.update(value_from_encryption, 16) ||
		    !hmac_ctx.finish(puser_key->data))
			return false;
		puser_key->length = 16;
		return true;
	}
	return false;
}

static bool ntlmssp_sess_key_ntlm2(const DATA_BLOB *pntv2_response,
	const uint8_t *part_passwd, const DATA_BLOB *psec_blob,
	const char *user, const char *domain, DATA_BLOB *puser_key)
{
	int user_len;
	int domain_len;
	uint8_t kr[16]; /* Finish the encryption of part_passwd. */
	char user_in[256];
	char tmp_user[UADDR_SIZE];
	char domain_in[256];
	DATA_BLOB client_key;
	uint8_t value_from_encryption[16];
	

	if (psec_blob->length != 8) {
		debug_info("[ntlmssp]: incorrect challenge size (%u) "
			"in sess_key_ntlm2", psec_blob->length);
		return false;
	}

	if (pntv2_response->length < 24) {
		debug_info("[ntlmssp]: incorrect password length (%u) "
			"in sess_key_ntlm2", pntv2_response->length);
		return false;
	}
	
	client_key.data = pntv2_response->data + 16;
	client_key.length = pntv2_response->length - 16;

	gx_strlcpy(tmp_user, user, GX_ARRAY_SIZE(tmp_user));
	HX_strupper(tmp_user);
	user_len = ntlmssp_utf8_to_utf16le(
		tmp_user, user_in, sizeof(user_in));
	domain_len = ntlmssp_utf8_to_utf16le(
		domain, domain_in, sizeof(domain_in));
	if (user_len < 0 || domain_len < 0) {
		return false;
	}

	HMACMD5_CTX hmac_ctx(part_passwd, 16);
	if (!hmac_ctx.is_valid() ||
	    !hmac_ctx.update(user_in, user_len) ||
	    !hmac_ctx.update(domain_in, domain_len) ||
	    !hmac_ctx.finish(kr))
		return false;

	hmac_ctx = HMACMD5_CTX(kr, 16);
	if (!hmac_ctx.is_valid() ||
	    !hmac_ctx.update(psec_blob->data, psec_blob->length) ||
	    !hmac_ctx.update(client_key.data, client_key.length) ||
	    !hmac_ctx.finish(value_from_encryption))
		return false;

	hmac_ctx = HMACMD5_CTX(kr, 16);
	if (!hmac_ctx.is_valid() ||
	    !hmac_ctx.update(value_from_encryption, 16) ||
	    !hmac_ctx.finish(puser_key->data))
		return false;
	puser_key->length = 16;
	return true;
}

static bool ntlmssp_server_chkpasswd(NTLMSSP_CTX *pntlmssp,
	DATA_BLOB *puser_key, DATA_BLOB *plm_key, const char *plain_passwd)
{
	DATA_BLOB tmp_key;
	const char *pdomain;
	DATA_BLOB *pchallenge;
	uint8_t tmp_key_buff[256];
	char upper_domain[128];
	const DATA_BLOB *plm_response;
	const DATA_BLOB *pnt_response;
	
	pchallenge = &pntlmssp->challenge.blob;
	plm_response = &pntlmssp->lm_resp;
	pnt_response = &pntlmssp->nt_resp;
	
	gx_strlcpy(upper_domain, pntlmssp->domain, GX_ARRAY_SIZE(upper_domain));
	HX_strupper(upper_domain);
	uint8_t nt_p16[16]{}, p16[16]{};
	if (!ntlmssp_md4hash(plain_passwd, nt_p16) ||
	    !ntlmssp_deshash(plain_passwd, p16))
		return false;
	
	if (pnt_response->length != 0 && pnt_response->length < 24) {
		debug_info("[ntlmssp]: invalid NT password length (%u) for user %s "
			"in server_chkpasswd", pnt_response->length, pntlmssp->user);
	}

	if (pnt_response->length > 24) {
		/* We have the NT MD4 hash challenge available - see if we can use it*/
		if (ntlmssp_check_ntlm2(pnt_response, nt_p16, pchallenge,
		    pntlmssp->user, pntlmssp->domain, puser_key) ||
		    ntlmssp_check_ntlm2(pnt_response, nt_p16, pchallenge,
		    pntlmssp->user, upper_domain, puser_key) ||
		    ntlmssp_check_ntlm2(pnt_response, nt_p16, pchallenge,
		    pntlmssp->user, "", puser_key)) {
			if (puser_key->length > 8) {
				memcpy(plm_key->data, puser_key->data, 8);
				plm_key->length = 8;
			} else {
				memcpy(plm_key->data, puser_key->data, puser_key->length);
				plm_key->length = puser_key->length;
			}
			return true;
		}
	} else if (24 == pnt_response->length) {
		if (ntlmssp_check_ntlm1(pnt_response, nt_p16,
		    pchallenge, puser_key)) {
			/* The LM session key for this response is not very secure, 
			   so use it only if we otherwise allow LM authentication */
			if (puser_key->length > 8) {
				memcpy(plm_key->data, p16, 8);
				plm_key->length = 8;
			} else {
				memcpy(plm_key->data, p16, puser_key->length);
				plm_key->length = puser_key->length;
			}
			return true;
		} else {
			return false;
		}
	} 
	

	if (0 == plm_response->length) {
		debug_info("[ntlmssp]: neither LanMan nor NT password supplied for "
			"user %s in server_chkpasswd", pntlmssp->user);
		return false;
	}

	if (plm_response->length < 24) {
		debug_info("[ntlmssp]: invalid LanMan password length (%u) for "
			"user %s in server_chkpasswd", pnt_response->length, pntlmssp->user);
		return false;
	}
	if (ntlmssp_check_ntlm1(plm_response, p16, pchallenge, nullptr)) {
		memset(puser_key->data, 0, 16);
		memcpy(puser_key->data, p16, 8);
		puser_key->length = 16;
		memcpy(plm_key->data, p16, 8);
		plm_key->length = 8;
		return true;
	}

	tmp_key.data = tmp_key_buff;
	tmp_key.length = 0;
	bool b_result = false;
	/* This is for 'LMv2' authentication.  almost NTLMv2 but limited to 24 bytes. */
	if (ntlmssp_check_ntlm2(plm_response, nt_p16, pchallenge,
	    pntlmssp->user, pntlmssp->domain, &tmp_key)) {
		b_result = true;
		pdomain = pntlmssp->domain;
	} else {
		if (ntlmssp_check_ntlm2(plm_response, nt_p16, pchallenge,
		    pntlmssp->user, upper_domain, &tmp_key)) {
			b_result = true;
			pdomain = upper_domain;
		} else {
			if (ntlmssp_check_ntlm2(plm_response, nt_p16, pchallenge,
			    pntlmssp->user, "", &tmp_key)) {
				b_result = true;
				pdomain = "";
			}
		}
	}
	
	if (b_result) {
		if (pnt_response->length > 24) {
			ntlmssp_sess_key_ntlm2(pnt_response, nt_p16, pchallenge, 
				pntlmssp->user, pdomain, puser_key);
		} else {
			/* Otherwise, use the LMv2 session key */
			memcpy(puser_key->data, tmp_key.data, tmp_key.length);
			puser_key->length = tmp_key.length;
		}
		if (0 != puser_key->length) {
			if (puser_key->length > 8) {
				memcpy(plm_key->data, puser_key->data, 8);
				plm_key->length = 8;
			} else {
				memcpy(plm_key->data, puser_key->data, puser_key->length);
				plm_key->length = puser_key->length;
			}
		}
		return true;
	}

	
	if (ntlmssp_check_ntlm1(plm_response, nt_p16, pchallenge, nullptr)) {
		/* The session key for this response is still very odd.  
		   It not very secure, so use it only if we otherwise 
		   allow LM authentication */	
			
		memset(puser_key->data, 0, 16);
		memcpy(puser_key->data, p16, 8);
		puser_key->length = 16;
		memcpy(plm_key->data, p16, 8);
		plm_key->length = 8;
		return true;
	}
	return false;
}

static bool ntlmssp_sign_init(NTLMSSP_CTX *pntlmssp)
{
	DATA_BLOB seal_key;
	DATA_BLOB weak_key;
	DATA_BLOB send_seal_blob;
	DATA_BLOB recv_seal_blob;
	uint8_t recv_seal_buff[16];
	uint8_t send_seal_buff[16];
	const char *send_sign_const;
	const char *send_seal_const;
	const char *recv_sign_const;
	const char *recv_seal_const;
	uint8_t weak_session_buff[8];
	

	if (pntlmssp->session_key.length < 8) {
		debug_info("[ntlmssp]: NO session key, cannot initialise "
			"signing in sign_init");
		return false;
	}
	memset(&pntlmssp->crypt, 0, sizeof(NTLMSSP_CRYPT_STATE));
	
	if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		weak_key = pntlmssp->session_key;
		send_seal_blob.data = send_seal_buff;
		send_seal_blob.length = sizeof(send_seal_buff);
		recv_seal_blob.data = recv_seal_buff;
		recv_seal_blob.length = sizeof(recv_seal_buff);

		send_sign_const = SRV_SIGN;
		send_seal_const = SRV_SEAL;
		recv_sign_const = CLI_SIGN;
		recv_seal_const = CLI_SEAL;

		if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_128) {
			/* do nothing */
		} else if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_56) {
			weak_key.length = 7;
		} else { /* forty bits */
			weak_key.length = 5;
		}
		
		/* SEND: sign key */
		if (!ntlmssp_calc_ntlm2_key(pntlmssp->crypt.ntlm2.sending.sign_key,
		    pntlmssp->session_key, send_sign_const))
			return false;
		
		/* SEND: seal ARCFOUR pad */
		if (!ntlmssp_calc_ntlm2_key(send_seal_buff, weak_key, send_seal_const))
			return false;
		arcfour_init(&pntlmssp->crypt.ntlm2.sending.seal_state,
		             send_seal_blob.pb, send_seal_blob.cb);

		/* SEND: seq num */
		pntlmssp->crypt.ntlm2.sending.seq_num = 0;

		/* RECV: sign key */
		if (!ntlmssp_calc_ntlm2_key(pntlmssp->crypt.ntlm2.receiving.sign_key,
		    pntlmssp->session_key, recv_sign_const))
			return false;

		/* RECV: seal ARCFOUR pad */
		if (!ntlmssp_calc_ntlm2_key(recv_seal_buff, weak_key, recv_seal_const))
			return false;

		arcfour_init(&pntlmssp->crypt.ntlm2.receiving.seal_state,
		             recv_seal_blob.pb, recv_seal_blob.cb);

		/* RECV: seq num */
		pntlmssp->crypt.ntlm2.receiving.seq_num = 0;
	} else {
		seal_key = pntlmssp->session_key;
		bool do_weak = false;
		
		if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_LM_KEY) {
			do_weak = true;
		}
		
		if (seal_key.length < 16) {
			/* TODO: is this really correct? */
			do_weak = false;
		}

		if (do_weak) {
			memcpy(weak_session_buff, seal_key.data, 8);
			seal_key.data = weak_session_buff;
			seal_key.length = 8;
			
			if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_56) {
				weak_session_buff[7] = 0xa0;
			} else { /* forty bits */
				weak_session_buff[5] = 0xe5;
				weak_session_buff[6] = 0x38;
				weak_session_buff[7] = 0xb0;
			}
		}

		arcfour_init(&pntlmssp->crypt.ntlm.seal_state,
		             seal_key.data, seal_key.cb);
		pntlmssp->crypt.ntlm.seq_num = 0;
	}
	return true;
}


/*
 * Next state function for the Authenticate packet
 * (after authentication - figures out the session keys etc)
 */
static bool ntlmssp_server_postauth(NTLMSSP_CTX *pntlmssp,
	NTLMSSP_SERVER_AUTH_STATE *pauth)
{
	DATA_BLOB *plm_key;
	DATA_BLOB *puser_key;
	DATA_BLOB session_key;
	uint8_t session_key_buff[32];
	static constexpr uint8_t zeros[24]{};

	plm_key = &pauth->lm_session_key;
	puser_key = &pauth->user_session_key;
	session_key.data = session_key_buff;
	session_key.length = 0;
	
	/* Handle the different session key derivation for NTLM2 */
	if (pauth->doing_ntlm2) {
		if (16 == puser_key->length) {
			HMACMD5_CTX hmac_ctx(puser_key->data, 16);
			if (!hmac_ctx.is_valid() ||
			    !hmac_ctx.update(pauth->session_nonce, sizeof(pauth->session_nonce)) ||
			    !hmac_ctx.finish(session_key.data))
				return false;
			session_key.length = 16;
		} else {
			session_key.length = 0;
		}
	} else if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_LM_KEY && 
		(0 == pntlmssp->nt_resp.length  || 24 == pntlmssp->nt_resp.length)) {
		if (plm_key->length >= 8) {
			if (24 == pntlmssp->lm_resp.length) {
				ntlmssp_lm_session_key(plm_key->data, pntlmssp->lm_resp.data,
					session_key.data);
			} else {
				ntlmssp_lm_session_key(zeros, zeros, session_key.data);
			}
			session_key.length = 16;
		} else {
			/* LM Key not selected */
			pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
			session_key.length = 0;
		}
	} else if (puser_key->length > 0) {
		memcpy(session_key.data, puser_key->data, puser_key->length);
		session_key.length = puser_key->length;
		/* LM Key not selected */
		pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
	} else if (plm_key->length > 0) {
		/* Very weird to have LM key, but no user session key, but anyway.. */
		memcpy(session_key.data, plm_key->data, plm_key->length);
		session_key.length = plm_key->length;
		/* LM Key not selected */
		pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
	} else {
		session_key.length = 0;
		/* LM Key not selected */
		pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
	}

	/* With KEY_EXCH, the client supplies the proposed session key,
	   but encrypts it with the long-term key */
	if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
		if (16 != pauth->encrypted_session_key.length) {
			return false;
		} else if (16 != session_key.length) {
			memcpy(pntlmssp->session_key.data, session_key.data,
				session_key.length);
			pntlmssp->session_key.length = session_key.length;
		} else {
			arcfour_crypt(pauth->encrypted_session_key.data, session_key.data,
				pauth->encrypted_session_key.length);
			memcpy(pntlmssp->session_key.data, pauth->encrypted_session_key.data,
				pauth->encrypted_session_key.length);
			pntlmssp->session_key.length = pauth->encrypted_session_key.length;
		}
	} else {
		memcpy(pntlmssp->session_key.data, session_key.data, session_key.length);
		pntlmssp->session_key.length = session_key.length;
	}

	if (0 != pntlmssp->session_key.length) {
		ntlmssp_sign_init(pntlmssp);
	}

	pntlmssp->expected_state = NTLMSSP_PROCESS_DONE;
	return true;
}

static bool ntlmssp_server_auth(NTLMSSP_CTX *pntlmssp,
	const DATA_BLOB in, DATA_BLOB *pout)
{
	char username[UADDR_SIZE];
	char plain_passwd[128];
	NTLMSSP_SERVER_AUTH_STATE auth_state;
	
	
	/* zero the outbound NTLMSSP packet */
	pout->length = 0;
	
	memset(&auth_state, 0, sizeof(NTLMSSP_SERVER_AUTH_STATE));
	if (!ntlmssp_server_preauth(pntlmssp, &auth_state, in))
		return false;
	auth_state.user_session_key.data = auth_state.user_session_key_buff;
	auth_state.user_session_key.length = 0;
	auth_state.lm_session_key.data = auth_state.lm_session_key_buff;
	auth_state.lm_session_key.length = 0;
	
	if (NULL == strchr(pntlmssp->user, '@')) {
			snprintf(username, GX_ARRAY_SIZE(username), "%s@%s",
			         pntlmssp->user, pntlmssp->domain);
		} else {
			gx_strlcpy(username, pntlmssp->user, GX_ARRAY_SIZE(username));
		}
		if (!pntlmssp->get_password(username, plain_passwd))
			return false;
	if (!ntlmssp_server_chkpasswd(pntlmssp, &auth_state.user_session_key,
	    &auth_state.lm_session_key, plain_passwd))
		return false;
	if (!ntlmssp_server_postauth(pntlmssp, &auth_state))
		return false;
	return true;
}

bool ntlmssp_update(NTLMSSP_CTX *pntlmssp, DATA_BLOB *pblob)
{
	DATA_BLOB tmp_blob;
	uint8_t blob_buff[1024];
	uint32_t ntlmssp_command;

	if (NTLMSSP_PROCESS_DONE == pntlmssp->expected_state) {
		return false;
	}
	if (0 == pblob->length) {
		return false;
	}
	if (!ntlmssp_parse_packet(*pblob, "Cd", "NTLMSSP", &ntlmssp_command))
		return false;
	if (ntlmssp_command != pntlmssp->expected_state) {
		debug_info("[ntlmssp]: got NTLMSSP command %u, expected %u "
			"in ntlmssp_update", ntlmssp_command, pntlmssp->expected_state);
		return false;
	}
	
	tmp_blob.data = blob_buff;
	tmp_blob.length = 0;
	
	if (NTLMSSP_PROCESS_NEGOTIATE == ntlmssp_command) {
		if (!ntlmssp_server_negotiate(pntlmssp, *pblob, &tmp_blob))
			return false;
	} else if (NTLMSSP_PROCESS_AUTH == ntlmssp_command) {
		if (!ntlmssp_server_auth(pntlmssp, *pblob, &tmp_blob))
			return false;
	} else {
		debug_info("[ntlmssp]: unexpected NTLMSSP command %u "
			"in ntlmssp_update", ntlmssp_command);
		return false;
	}
	
	free(pblob->data);
	if (0 == tmp_blob.length) {
		pblob->data = NULL;
	} else {
		pblob->data = me_alloc<uint8_t>(tmp_blob.length);
		if (NULL == pblob->data) {
			return false;
		}
		memcpy(pblob->data, tmp_blob.data, tmp_blob.length);
	}
	pblob->length = tmp_blob.length;
	return true;
}

uint32_t ntlmssp_expected_state(NTLMSSP_CTX *pntlmssp)
{
	return pntlmssp->expected_state;
}

size_t ntlmssp_sig_size()
{
	return NTLMSSP_SIG_SIZE;
}

static bool ntlmssp_make_packet_signature(NTLMSSP_CTX *pntlmssp,
    const uint8_t *pdata, size_t length, const uint8_t *pwhole_pdu,
    size_t pdu_length, int direction, DATA_BLOB *psig, bool encrypt_sig)
{
	uint32_t crc;
	uint8_t digest[16];
	uint8_t seq_num[4];
	
	if (!(pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_NTLM2)) {
		crc = crc32_calc_buffer(pdata, length);
		if (!ntlmssp_gen_packet(psig, "dddd", NTLMSSP_SIGN_VERSION,
		    0, crc, pntlmssp->crypt.ntlm.seq_num))
			return false;
		pntlmssp->crypt.ntlm.seq_num ++;
		arcfour_crypt_sbox(&pntlmssp->crypt.ntlm.seal_state,
			psig->data + 4, psig->length - 4);
		return true;
	}

	HMACMD5_CTX hmac_ctx;
	switch (direction) {
	case NTLMSSP_DIRECTION_SEND:
		cpu_to_le32p(seq_num, pntlmssp->crypt.ntlm2.sending.seq_num);
		pntlmssp->crypt.ntlm2.sending.seq_num ++;
		hmac_ctx = HMACMD5_CTX(pntlmssp->crypt.ntlm2.sending.sign_key, 16);
		break;
	case NTLMSSP_DIRECTION_RECEIVE:
		cpu_to_le32p(seq_num, pntlmssp->crypt.ntlm2.receiving.seq_num);
		pntlmssp->crypt.ntlm2.receiving.seq_num ++;
		hmac_ctx = HMACMD5_CTX(pntlmssp->crypt.ntlm2.receiving.sign_key, 16);
		break;
	}

	if (!hmac_ctx.is_valid() ||
	    !hmac_ctx.update(seq_num, sizeof(seq_num)) ||
	    !hmac_ctx.update(pwhole_pdu, pdu_length) ||
	    !hmac_ctx.finish(digest))
		return false;

	if (encrypt_sig && (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH)) {
		switch (direction) {
		case NTLMSSP_DIRECTION_SEND:
			arcfour_crypt_sbox(&pntlmssp->crypt.ntlm2.sending.seal_state,
				digest, 8);
			break;
		case NTLMSSP_DIRECTION_RECEIVE:
			arcfour_crypt_sbox(&pntlmssp->crypt.ntlm2.receiving.seal_state,
				digest, 8);
			break;
		}
	}

	cpu_to_le32p(&psig->data[0], NTLMSSP_SIGN_VERSION);
	memcpy(psig->data + 4, digest, 8);
	memcpy(psig->data + 12, seq_num, 4);
	psig->length = NTLMSSP_SIG_SIZE;
	return true;
}

bool ntlmssp_sign_packet(NTLMSSP_CTX *pntlmssp, const uint8_t *pdata,
	size_t length, const uint8_t *pwhole_pdu, size_t pdu_length,
	DATA_BLOB *psig)
{
	std::lock_guard lk(pntlmssp->lock);
	if (!(pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_SIGN) ||
		0 == pntlmssp->session_key.length) {
		return false;
	}
	if (!ntlmssp_make_packet_signature(pntlmssp, pdata, length, pwhole_pdu,
	    pdu_length, NTLMSSP_DIRECTION_SEND, psig, true)) {
		return false;
	}
	return true;
}

static bool ntlmssp_check_packet_internal(NTLMSSP_CTX *pntlmssp,
	const uint8_t *pdata, size_t length, const uint8_t *pwhole_pdu,
	size_t pdu_length, const DATA_BLOB *psig)
{
	DATA_BLOB local_sig;
	uint8_t local_sig_buff[16];
	
	local_sig.data = local_sig_buff;
	if (0 == pntlmssp->session_key.length) {
		return false;
	}
	
	if (0 == pntlmssp->session_key.length) {
		debug_info("[ntlm]: no session key, cannot check packet signature\n");
		return false;
	}

	if (psig->length < 8) {
		debug_info("[ntlmssp]: NTLMSSP packet check failed due to short "
			"signature (%u bytes)! in check_packet", psig->length);
	}
	if (!ntlmssp_make_packet_signature(pntlmssp, pdata, length, pwhole_pdu,
	    pdu_length, NTLMSSP_DIRECTION_RECEIVE, &local_sig, true))
		return false;

	if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		if (local_sig.length != psig->length ||
			memcmp(local_sig.data, psig->data, psig->length) != 0) {
			debug_info("[ntlmssp]: NTLMSSP NTLM2 packet check failed due to "
				"invalid signature!\n");
			return false;
		}
	} else {
		if (local_sig.length != psig->length || memcmp(local_sig.data + 8,
			psig->data + 8, psig->length - 8) != 0) {
			debug_info("[ntlmssp]: NTLMSSP NTLM1 packet check failed due to "
				"invalid signature!\n");
			return false;
		}
	}
	return true;
}

bool ntlmssp_check_packet(NTLMSSP_CTX *pntlmssp, const uint8_t *pdata,
	size_t length, const uint8_t *pwhole_pdu, size_t pdu_length,
	const DATA_BLOB *psig)
{
	std::lock_guard lk(pntlmssp->lock);
	if (!ntlmssp_check_packet_internal(pntlmssp, pdata, length, pwhole_pdu,
	    pdu_length, psig)) {
		return false;
	}
	return true;
}

bool ntlmssp_seal_packet(NTLMSSP_CTX *pntlmssp, uint8_t *pdata, size_t length,
	const uint8_t *pwhole_pdu, size_t pdu_length, DATA_BLOB *psig)
{
	uint32_t crc;
	
	if (!(pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_SEAL))
		return false;
	if (!(pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_SIGN))
		return false;
	std::lock_guard lk(pntlmssp->lock);
	if (0 == pntlmssp->session_key.length) {
		debug_info("[ntlm]: no session key, cannot seal packet\n");
		return false;
	}
	if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		if (!ntlmssp_make_packet_signature(pntlmssp, pdata, length,
		    pwhole_pdu, pdu_length, NTLMSSP_DIRECTION_SEND, psig, false)) {
			return false;
		}

		arcfour_crypt_sbox(&pntlmssp->crypt.ntlm2.sending.seal_state,
			pdata, length);
		if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
			arcfour_crypt_sbox(&pntlmssp->crypt.ntlm2.sending.seal_state,
				psig->data + 4, 8);
		}
	} else {
		crc = crc32_calc_buffer(pdata, length);
		if (!ntlmssp_gen_packet(psig, "dddd", NTLMSSP_SIGN_VERSION,
		    0, crc, pntlmssp->crypt.ntlm.seq_num)) {
			return false;
		}
		
		arcfour_crypt_sbox(&pntlmssp->crypt.ntlm.seal_state, pdata, length);
		arcfour_crypt_sbox(&pntlmssp->crypt.ntlm.seal_state,
			psig->data + 4, psig->length - 4);
		pntlmssp->crypt.ntlm.seq_num ++;
	}
	return true;
}
	
bool ntlmssp_unseal_packet(NTLMSSP_CTX *pntlmssp, uint8_t *pdata,
	size_t length, const uint8_t *pwhole_pdu, size_t pdu_length,
	const DATA_BLOB *psig)
{
	std::lock_guard lk(pntlmssp->lock);
	if (0 == pntlmssp->session_key.length) {
		debug_info("[ntlm]: no session key, cannot unseal packet\n");
		return false;
	}
	if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		/* First unseal the data. */
		arcfour_crypt_sbox(&pntlmssp->crypt.ntlm2.receiving.seal_state,
			pdata, length);
	} else {
		arcfour_crypt_sbox(&pntlmssp->crypt.ntlm.seal_state, pdata, length);
	}
	if (!ntlmssp_check_packet_internal(pntlmssp, pdata, length, pwhole_pdu,
	    pdu_length, psig)) {
		return false;
	}
	return true;
}

static bool ntlmssp_session_key(NTLMSSP_CTX *pntlmssp, DATA_BLOB *psession_key)
{
	if (pntlmssp->expected_state != NTLMSSP_PROCESS_DONE) {
		return false;
	}

	if (0 == pntlmssp->session_key.length) {
		return false;
	}
	memcpy(psession_key->data, pntlmssp->session_key.data,
		pntlmssp->session_key.length);
	psession_key->length = pntlmssp->session_key.length;
	return true;
}

bool ntlmssp_session_info(NTLMSSP_CTX *pntlmssp, NTLMSSP_SESSION_INFO *psession)
{
	if (NULL == strchr(pntlmssp->user, '@')) {
		snprintf(psession->username, GX_ARRAY_SIZE(psession->username),
		         "%s@%s", pntlmssp->user, pntlmssp->domain);
	} else {
		gx_strlcpy(psession->username, pntlmssp->user, GX_ARRAY_SIZE(psession->username));
	}
	psession->session_key.data = psession->session_key_buff;
	return ntlmssp_session_key(pntlmssp, &psession->session_key);
}

void ntlmssp_destroy(NTLMSSP_CTX *pntlmssp)
{
	delete pntlmssp;
}
