// SPDX-License-Identifier: GPL-3.0-or-later
#include <algorithm>
#include <cerrno>
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

/* G(x) = x^32+x^26+x^23+x^22+x^16+x^12+x^11+x^10+x^8+x^7+x^5+x^4+x^2+x^1+x^0 */
static constexpr uint32_t crc32_tab[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

static uint32_t crc32_calc_buffer(const uint8_t *p, size_t z)
{
	/*
	 * SPDX-License-Identifier: BSD-2-Clause
	 * COPYRIGHT (C) 1986 Gary S. Brown.  You may use this program, or
	 * code or tables extracted from it, as desired without restriction.
	 * (Details in FreeBSD's copy.)
	 */
	uint32_t crc = ~0U;
	for (; z-- > 0; ++p)
		crc = crc32_tab[(crc ^ *p) & 0xFF] ^ (crc >> 8);
	return ~crc;
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
	if (EVP_DigestUpdate(ctx.get(), session_key.pb, session_key.cb) <= 0 ||
	    EVP_DigestUpdate(ctx.get(), constant, strlen(constant) + 1) <= 0 ||
	    EVP_DigestFinal(ctx.get(), subkey, nullptr) <= 0)
		return false;
	return true;
}

static ssize_t ntlmssp_utf8_to_utf16le(const char *src, void *dst, size_t len)
{
	size_t in_len;
	size_t out_len;
	iconv_t conv_id;

	len = std::min(len, static_cast<size_t>(SSIZE_MAX));
	conv_id = iconv_open("UTF-16LE", "UTF-8");
	if (conv_id == (iconv_t)-1) {
		mlog(LV_ERR, "E-2112: iconv_open: %s", strerror(errno));
		return -1;
	}
	auto pin  = deconst(src);
	auto pout = static_cast<char *>(dst);
	in_len = strlen(src);
	memset(dst, 0, len);
	out_len = len;
	if (iconv(conv_id, &pin, &in_len, &pout, &len) == static_cast<size_t>(-1)) {
		iconv_close(conv_id);
		return -1;
	}
	iconv_close(conv_id);
	return out_len - len;
}

static bool ntlmssp_utf16le_to_utf8(const void *src, size_t src_len,
	char *dst, size_t len)
{
	char *pin, *pout;
	iconv_t conv_id;

	conv_id = iconv_open("UTF-8", "UTF-16LE");
	if (conv_id == (iconv_t)-1) {
		mlog(LV_ERR, "E-2113: iconv_open: %s", strerror(errno));
		return false;
	}
	pin = (char*)src;
	pout = dst;
	memset(dst, 0, len);
	if (iconv(conv_id, &pin, &src_len, &pout, &len) == static_cast<size_t>(-1)) {
		iconv_close(conv_id);
		return false;
	}
	iconv_close(conv_id);
	return true;
}

static bool ntlmssp_md4hash(const char *passwd, void *p16v)
{
	auto p16 = static_cast<uint8_t *>(p16v);
	char upasswd[256];

	memset(p16, 0, MD4_DIGEST_LENGTH);
	auto passwd_len = ntlmssp_utf8_to_utf16le(passwd, upasswd, sizeof(upasswd));
	if (passwd_len < 0)
		return false;
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
static bool ntlmssp_gen_packetv(DATA_BLOB *pblob, const char *format,
    va_list ap)
{
	char *s;
	int i, j;
	uint8_t *b;
	uint32_t length;
	int intargs[64]{};
	uint8_t buffs[64][1024]{};
	DATA_BLOB blobs[64]{};
	int head_ofs, data_ofs;
	int head_size, data_size;
	
	if (strlen(format) > sizeof(blobs) / sizeof(DATA_BLOB))
		return false;
	memset(blobs, 0, sizeof(blobs));
	head_size = 0;
	data_size = 0;
	/* first scan the format to work out the header and body size */
	for (i=0; format[i]; i++) {
		switch (format[i]) {
		case 'U': {
			s = va_arg(ap, char*);
			head_size += 8;
			auto ret = ntlmssp_utf8_to_utf16le(s, buffs[i], std::size(buffs[i]));
			if (ret < 0)
				return false;
			blobs[i].cb = ret;
			blobs[i].pb = buffs[i];
			data_size += blobs[i].cb;
			break;
		}
		case 'A':
			s = va_arg(ap, char*);
			head_size += 8;
			blobs[i].pc = s;
			blobs[i].cb = strlen(s);
			data_size += blobs[i].cb;
			break;
		case 'a': {
			j = va_arg(ap, int);
			intargs[i] = j;
			s = va_arg(ap, char*);
			auto ret = ntlmssp_utf8_to_utf16le(s, buffs[i], std::size(buffs[i]));
			if (ret < 0)
				return false;
			blobs[i].cb = ret;
			blobs[i].pb = buffs[i];
			data_size += blobs[i].cb + 4;
			break;
		}
		case 'B':
			b = va_arg(ap, uint8_t*);
			head_size += 8;
			blobs[i].pb = b;
			blobs[i].cb = va_arg(ap, int);
			data_size += blobs[i].cb;
			break;
		case 'b':
			b = va_arg(ap, uint8_t*);
			blobs[i].pb = b;
			blobs[i].cb = va_arg(ap, int);
			head_size += blobs[i].cb;
			break;
		case 'd':
			j = va_arg(ap, int);
			intargs[i] = j;
			head_size += 4;
			break;
		case 'C':
			s = va_arg(ap, char*);
			blobs[i].pc = s;
			blobs[i].cb = strlen(s) + 1;
			head_size += blobs[i].cb;
			break;
		default:
			return false;
		}
	}

	if (head_size + data_size == 0)
		return false;
	head_ofs = 0;
	data_ofs = head_size;

	for (i=0; format[i]; i++) {
		switch (format[i]) {
		case 'U':
		case 'A':
		case 'B':
			length = blobs[i].cb;
			cpu_to_le16p(&pblob->pb[head_ofs], length);
			head_ofs += 2;
			cpu_to_le16p(&pblob->pb[head_ofs], length);
			head_ofs += 2;
			cpu_to_le32p(&pblob->pb[head_ofs], data_ofs);
			head_ofs += 4;
			if (blobs[i].pb != nullptr && length > 0)
				/* don't follow null blobs... */
				memcpy(&pblob->pb[data_ofs], blobs[i].pb, length);
			data_ofs += length;
			break;
		case 'a':
			cpu_to_le16p(&pblob->pb[data_ofs], intargs[i]);
			data_ofs += 2;
			length = blobs[i].cb;
			cpu_to_le16p(&pblob->pb[data_ofs], length);
			data_ofs += 2;
			memcpy(&pblob->pb[data_ofs], blobs[i].pb, length);
			data_ofs += length;
			break;
		case 'd':
			cpu_to_le32p(&pblob->pb[head_ofs], intargs[i]);
			head_ofs += 4;
			break;
		case 'b':
			length = blobs[i].cb;
			if (blobs[i].pb != nullptr && length > 0)
				/* don't follow null blobs... */
				memcpy(&pblob->pb[head_ofs], blobs[i].pb, length);
			head_ofs += length;
			break;
		case 'C':
			length = blobs[i].cb;
			memcpy(&pblob->pb[head_ofs], blobs[i].pb, length);
			head_ofs += length;
			break;
		default:
			return false;
		}
	}
	pblob->cb = head_size + data_size;
	return true;
}

static bool ntlmssp_gen_packet(DATA_BLOB *pblob, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	auto ret = ntlmssp_gen_packetv(pblob, format, ap);
	va_end(ap);
	return ret;
}

/*
  format specifiers are:

  U = unicode string (output is utf8, input first 4 bytes for buffer length)
  A = ascii string
  B = data blob (input blob.cb of buffer length)
  b = data blob in header (input blob.cb of buffer length)
  d = word (4 bytes)
  C = constant ascii string
 */
static bool ntlmssp_parse_packetv(const DATA_BLOB blob, const char *format,
    va_list ap)
{
	int i;
	char *ps;
	uint32_t *v;
	uintptr_t head_ofs = 0, ptr_ofs = 0;
	DATA_BLOB *pblob;
	uint16_t len1, len2;
	
	for (i=0; format[i]; i++) {
		switch (format[i]) {
		case 'U':
			if (head_ofs + 8 > blob.cb)
				return false;
			len1 = le16p_to_cpu(&blob.pb[head_ofs]);
			head_ofs += 2;
			len2 = le16p_to_cpu(&blob.pb[head_ofs]);
			head_ofs += 2;
			ptr_ofs = le32p_to_cpu(&blob.pb[head_ofs]);
			head_ofs += 4;

			ps = va_arg(ap, char*);
			if (0 == len1 && 0 == len2) {
				ps[0] = '\0';
				break;
			}
			/* make sure its in the right format - be strict */
			if (len1 != len2 || ptr_ofs + len1 < ptr_ofs ||
			    ptr_ofs + len1 < len1 || ptr_ofs + len1 > blob.cb)
				return false;
			if (len1 & 1)
				/* if odd length and unicode */
				return false;
			if (&blob.pb[ptr_ofs] < reinterpret_cast<uint8_t *>(ptr_ofs) ||
			    &blob.pb[ptr_ofs] < blob.pb)
				return false;
			if (!ntlmssp_utf16le_to_utf8(&blob.pb[ptr_ofs],
			    len1, ps, le32p_to_cpu(ps)))
				return false;
			break;
		case 'A':
			if (head_ofs + 8 > blob.cb)
				return false;
			len1 = le16p_to_cpu(&blob.pb[head_ofs]);
			head_ofs += 2;
			len2 = le16p_to_cpu(&blob.pb[head_ofs]);
			head_ofs += 2;
			ptr_ofs = le32p_to_cpu(&blob.pb[head_ofs]);
			head_ofs += 4;

			ps = va_arg(ap, char*);
			/* make sure its in the right format - be strict */
			if (0 == len1 && 0 == len2) {
				ps[0] = '\0';
				break;
			}
			if (len1 != len2 || ptr_ofs + len1 < ptr_ofs ||
			    ptr_ofs + len1 < len1 || ptr_ofs + len1 > blob.cb)
				return false;
			if (&blob.pb[ptr_ofs] < reinterpret_cast<uint8_t *>(ptr_ofs) ||
			    &blob.pb[ptr_ofs] < blob.pb)
				return false;
			if (len1 > 0) {
				memcpy(ps, &blob.pb[ptr_ofs], len1);
				ps[len1] = '\0';
			}
			break;
		case 'B':
			if (head_ofs + 8 > blob.cb)
				return false;
			len1 = le16p_to_cpu(&blob.pb[head_ofs]);
			head_ofs += 2;
			len2 = le16p_to_cpu(&blob.pb[head_ofs]);
			head_ofs += 2;
			ptr_ofs = le32p_to_cpu(&blob.pb[head_ofs]);
			head_ofs += 4;

			pblob = (DATA_BLOB*)va_arg(ap, void*);
			if (0 == len1 && 0 == len2) {
				pblob->cb = 0;
				break;
			}
			/* make sure its in the right format - be strict */
			if (len1 != len2 || ptr_ofs + len1 < ptr_ofs ||
			    ptr_ofs + len1 < len1 || ptr_ofs + len1 > blob.cb)
				return false;
			if (&blob.pb[ptr_ofs] < reinterpret_cast<uint8_t *>(ptr_ofs) ||
			    &blob.pb[ptr_ofs] < blob.pb || pblob->cb < len1)
				return false;
			memcpy(pblob->pb, &blob.pb[ptr_ofs], len1);
			pblob->cb = len1;
			break;
		case 'b':
			pblob = (DATA_BLOB *)va_arg(ap, void*);
			len1 = va_arg(ap, unsigned int);
			/* make sure its in the right format - be strict */
			if (head_ofs + len1 > blob.cb)
				return false;
			if (&blob.pb[head_ofs] < reinterpret_cast<uint8_t *>(head_ofs) ||
			    &blob.pb[head_ofs] < blob.pb || pblob->cb < len1)
				return false;
			memcpy(pblob->pb, &blob.pb[head_ofs], len1);
			pblob->cb = len1;
			head_ofs += len1;
			break;
		case 'd':
			v = va_arg(ap, uint32_t*);
			if (head_ofs + 4 > blob.cb)
				return false;
			*v = le32p_to_cpu(&blob.pb[head_ofs]);
			head_ofs += 4;
			break;
		case 'C':
			ps = va_arg(ap, char*);

			if (&blob.pb[head_ofs] < reinterpret_cast<uint8_t *>(head_ofs) ||
			    &blob.pb[head_ofs] < blob.pb ||
			    head_ofs + strlen(ps) + 1 > blob.cb)
				return false;
			if (memcmp(&blob.pb[head_ofs], ps, strlen(ps) + 1) != 0)
				return false;
			head_ofs += strlen(ps) + 1;
			break;
		}
	}
	return true;
}

static bool ntlmssp_parse_packet(const DATA_BLOB blob, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	auto ret = ntlmssp_parse_packetv(blob, format, ap);
	va_end(ap);
	return ret;
}

/* neg_flags can be one or more following
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
	gx_strlcpy(pntlmssp->netbios_name, netbios_name, std::size(pntlmssp->netbios_name));
	gx_strlcpy(pntlmssp->dns_name, dns_name, std::size(pntlmssp->dns_name));
	gx_strlcpy(pntlmssp->dns_domain, dns_domain, std::size(pntlmssp->dns_domain));
	pntlmssp->get_password = get_password;
	return pntlmssp;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1645: ENOMEM");
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
	if (neg_flags & NTLMSSP_REQUEST_TARGET)
		pntlmssp->neg_flags |= NTLMSSP_REQUEST_TARGET;
}


static const char *ntlmssp_target_name(NTLMSSP_CTX *pntlmssp,
	uint32_t neg_flags, uint32_t *chal_flags)
{
	if (!(neg_flags & NTLMSSP_REQUEST_TARGET))
		return "";
	*chal_flags |= NTLMSSP_NEGOTIATE_TARGET_INFO;
	*chal_flags |= NTLMSSP_REQUEST_TARGET;
	*chal_flags |= NTLMSSP_TARGET_TYPE_SERVER;
	return pntlmssp->dns_name;
}

static pack_result ntlmssp_ndr_push_ntlm_version(NDR_PUSH *pndr, NTLMSSP_VERSION *r)
{
	auto status = pndr->align(2);
	if (status != pack_result::success)
		return status;
	status = pndr->p_uint8(r->major_vers);
	if (status != pack_result::success)
		return status;
	status = pndr->p_uint8(r->minor_vers);
	if (status != pack_result::success)
		return status;
	status = pndr->p_uint16(r->product_build);
	if (status != pack_result::success)
		return status;
	status = pndr->p_uint8_a(r->reserved, 3);
	if (status != pack_result::success)
		return status;
	status = pndr->p_uint8(r->ntlm_revers);
	if (status != pack_result::success)
		return status;
	return pndr->trailer_align(2);
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
	if (request.cb != 0 && (request.cb < 16 || !ntlmssp_parse_packet(request,
	    "Cdd", "NTLMSSP", &ntlmssp_command, &neg_flags)))
		return false;

	ntlmssp_handle_neg_flags(pntlmssp, neg_flags);
	if (pntlmssp->challenge.blob.cb > 0) {
		/* get the previous challenge */
		memcpy(cryptkey, pntlmssp->challenge.blob.pb, 8);
	} else {
		/* produce cryptkey and copy it to challenge */
		randstring(cryptkey, 8);
		pntlmssp->challenge.blob.pb = pntlmssp->challenge.blob_buff;
		memcpy(pntlmssp->challenge.blob_buff, cryptkey, 8);
		pntlmssp->challenge.blob.cb = 8;
	}
	
	
	/* The flags we send back are not just the negotiated flags,
	 * they are also 'what is in this packet'.  Therefore, we
	 * operate on 'chal_flags' from here on
	 */

	chal_flags = pntlmssp->neg_flags;

	/* get the right name to fill in as 'target' */
	target_name = ntlmssp_target_name(pntlmssp, neg_flags, &chal_flags);

	pntlmssp->internal_chal.pb = pntlmssp->internal_chal_buff;
	memcpy(pntlmssp->internal_chal.pb, cryptkey, 8);
	pntlmssp->internal_chal.cb = 8;
	struct_blob.pb = struct_blob_buff;
	struct_blob.cb = 0;
	if (chal_flags & NTLMSSP_NEGOTIATE_TARGET_INFO) {
		if (!ntlmssp_gen_packet(&struct_blob, "aaaaa",
		    MSVAVNBDOMAINNAME, target_name,
		    MSVAVNBCOMPUTERNAME, pntlmssp->netbios_name,
		    MSVAVDNSDOMAINNAME, pntlmssp->dns_domain,
		    MSVAVDNSCOMPUTERNAME, pntlmssp->dns_name,
		    MSVAVEOL, ""))
			return false;
	} else {
		struct_blob.pb = nullptr;
		struct_blob.cb = 0;
	}

	
	/* Marshal the packet in the right format, unicode or ASCII */
	version_blob.pb = nullptr;
	version_blob.cb = 0;
	
	if (chal_flags & NTLMSSP_NEGOTIATE_VERSION) {
		memset(&vers, 0, sizeof(NTLMSSP_VERSION));
		vers.major_vers = NTLMSSP_WINDOWS_MAJOR_VERSION_6;
		vers.minor_vers = NTLMSSP_WINDOWS_MINOR_VERSION_1;
		vers.product_build = 0;
		vers.ntlm_revers = NTLMSSP_REVISION_W2K3;
		
		ndr_push.init(ndr_buff, sizeof(ndr_buff), 0);
		if (ntlmssp_ndr_push_ntlm_version(&ndr_push, &vers) != pack_result::success)
			return false;
		version_blob.pb = ndr_push.data;
		version_blob.cb = ndr_push.offset;
	}
		
	if (pntlmssp->unicode)
		parse_string = "CdUdbddBb";
	else
		parse_string = "CdAdbddBb";
	if (!ntlmssp_gen_packet(preply, parse_string, "NTLMSSP",
	    NTLMSSP_PROCESS_CHALLENGE, target_name, chal_flags, cryptkey,
	    8, 0, 0, struct_blob.pb, struct_blob.cb, version_blob.pb,
	    version_blob.cb))
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

	pntlmssp->session_key.pb = pntlmssp->session_key_buff;
	pntlmssp->session_key.cb = 0;
	pntlmssp->lm_resp.pb = pntlmssp->lm_resp_buff;
	pntlmssp->lm_resp.cb = sizeof(pntlmssp->lm_resp_buff);
	pntlmssp->nt_resp.pb = pntlmssp->nt_resp_buff;
	pntlmssp->nt_resp.cb = sizeof(pntlmssp->nt_resp_buff);
	
	pntlmssp->user[0] = '\0';
	pntlmssp->domain[0] = '\0';
	pauth->encrypted_session_key.pb = pauth->encrypted_session_key_buff;
	pauth->encrypted_session_key.cb = sizeof(pauth->encrypted_session_key_buff);
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
		pauth->encrypted_session_key.cb = 0;
		auth_flags = 0;
		
		cpu_to_le32p(pntlmssp->domain, sizeof(pntlmssp->domain));
		cpu_to_le32p(pntlmssp->user, sizeof(pntlmssp->user));
		cpu_to_le32p(client_netbios_name, sizeof(client_netbios_name));
		pntlmssp->lm_resp.cb = std::size(pntlmssp->lm_resp_buff);
		pntlmssp->nt_resp.cb = std::size(pntlmssp->nt_resp_buff);
		/* now the NTLMSSP encoded auth hashes */
		if (!ntlmssp_parse_packet(request, parse_string, "NTLMSSP",
		    &ntlmssp_command, &pntlmssp->lm_resp, &pntlmssp->nt_resp,
		    pntlmssp->domain, pntlmssp->user, client_netbios_name))
			return false;
	}

	if (auth_flags != 0)
		ntlmssp_handle_neg_flags(pntlmssp, auth_flags);
	if (!(pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) ||
	    pntlmssp->nt_resp.cb != 24 || pntlmssp->lm_resp.cb != 24)
		return true;
	pauth->doing_ntlm2 = true;
	memcpy(pauth->session_nonce, pntlmssp->internal_chal.pb, 8);
	memcpy(pauth->session_nonce + 8, pntlmssp->lm_resp.pb, 8);

	std::unique_ptr<EVP_MD_CTX, sslfree> ctx(EVP_MD_CTX_new());
	if (ctx == nullptr ||
	    EVP_DigestInit(ctx.get(), EVP_md5()) <= 0 ||
	    EVP_DigestUpdate(ctx.get(), pauth->session_nonce, 16) <= 0 ||
	    EVP_DigestFinal(ctx.get(), session_nonce_hash, nullptr) <= 0)
		return false;

	/* LM response is no longer useful */
	pntlmssp->lm_resp.cb = 0;
	memcpy(pntlmssp->challenge.blob.pb, session_nonce_hash, 8);
	pntlmssp->challenge.blob.cb = 8;

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
	
	if (psec_blob->cb != 8) {
		mlog(LV_DEBUG, "ntlmssp: incorrect challenge size (%u) in check_ntlm1",
			psec_blob->cb);
		return false;
	}
	if (pnt_response->cb != 24) {
		mlog(LV_DEBUG, "ntlmssp: incorrect password length (%u) in check_ntlm1",
			pnt_response->cb);
		return false;
	}

	memset(p21, 0, sizeof(p21));
	memcpy(p21, part_passwd, 16);
	if (!E_P24(p21, psec_blob->pb, p24))
		return false;
	if (memcmp(p24, pnt_response->pb, 24) != 0)
		return false;
	if (puser_key == nullptr)
		return true;
	std::unique_ptr<EVP_MD_CTX, sslfree> ctx(EVP_MD_CTX_new());
	if (ctx == nullptr ||
	    EVP_DigestInit(ctx.get(), EVP_md4()) <= 0 ||
	    EVP_DigestUpdate(ctx.get(), part_passwd, 16) <= 0 ||
	    EVP_DigestFinal(ctx.get(), puser_key->pb, nullptr) <= 0)
		return false;
	puser_key->cb = 16;
	return true;
}

static bool ntlmssp_check_ntlm2(const DATA_BLOB *pntv2_response,
	const uint8_t *part_passwd, const DATA_BLOB *psec_blob,
	const char *user, const char *domain, DATA_BLOB *puser_key)
{
	uint8_t kr[16]; /* Finish the encryption of part_passwd. */
	char user_in[256];
	char tmp_user[UADDR_SIZE];
	char domain_in[256];
	DATA_BLOB client_key;
	uint8_t value_from_encryption[16];

	if (psec_blob->cb != 8) {
		mlog(LV_DEBUG, "ntlmssp: incorrect challenge size (%u) "
			"in check_ntlm2", psec_blob->cb);
		return false;
	}
	if (pntv2_response->cb < 24) {
		mlog(LV_DEBUG, "ntlmssp: incorrect password length (%u) "
			"in check_ntlm2", pntv2_response->cb);
		return false;
	}

	client_key.pb = &pntv2_response->pb[16];
	client_key.cb = pntv2_response->cb - 16;
	gx_strlcpy(tmp_user, user, std::size(tmp_user));
	HX_strupper(tmp_user);
	auto user_len = ntlmssp_utf8_to_utf16le(tmp_user, user_in, sizeof(user_in));
	auto domain_len = ntlmssp_utf8_to_utf16le(domain, domain_in, sizeof(domain_in));
	if (user_len < 0 || domain_len < 0)
		return false;

	HMACMD5_CTX hmac_ctx(part_passwd, 16);
	if (!hmac_ctx.is_valid() ||
	    !hmac_ctx.update(user_in, user_len) ||
	    !hmac_ctx.update(domain_in, domain_len) ||
	    !hmac_ctx.finish(kr))
		return false;

	hmac_ctx = HMACMD5_CTX(kr, 16);
	if (!hmac_ctx.is_valid() ||
	    !hmac_ctx.update(psec_blob->pb, psec_blob->cb) ||
	    !hmac_ctx.update(client_key.pb, client_key.cb) ||
	    !hmac_ctx.finish(value_from_encryption))
		return false;

	if (memcmp(value_from_encryption, pntv2_response->pb, 16) == 0) {
		hmac_ctx = HMACMD5_CTX(kr, 16);
		if (!hmac_ctx.is_valid() ||
		    !hmac_ctx.update(value_from_encryption, 16) ||
		    !hmac_ctx.finish(puser_key->pb))
			return false;
		puser_key->cb = 16;
		return true;
	}
	return false;
}

static bool ntlmssp_sess_key_ntlm2(const DATA_BLOB *pntv2_response,
	const uint8_t *part_passwd, const DATA_BLOB *psec_blob,
	const char *user, const char *domain, DATA_BLOB *puser_key)
{
	uint8_t kr[16]; /* Finish the encryption of part_passwd. */
	char user_in[256];
	char tmp_user[UADDR_SIZE];
	char domain_in[256];
	DATA_BLOB client_key;
	uint8_t value_from_encryption[16];
	
	if (psec_blob->cb != 8) {
		mlog(LV_DEBUG, "ntlmssp: incorrect challenge size (%u) "
			"in sess_key_ntlm2", psec_blob->cb);
		return false;
	}
	if (pntv2_response->cb < 24) {
		mlog(LV_DEBUG, "ntlmssp: incorrect password length (%u) "
			"in sess_key_ntlm2", pntv2_response->cb);
		return false;
	}
	
	client_key.pb = &pntv2_response->pb[16];
	client_key.cb = pntv2_response->cb - 16;
	gx_strlcpy(tmp_user, user, std::size(tmp_user));
	HX_strupper(tmp_user);
	auto user_len = ntlmssp_utf8_to_utf16le(tmp_user, user_in, std::size(user_in));
	auto domain_len = ntlmssp_utf8_to_utf16le(domain, domain_in, std::size(domain_in));
	if (user_len < 0 || domain_len < 0)
		return false;

	HMACMD5_CTX hmac_ctx(part_passwd, 16);
	if (!hmac_ctx.is_valid() ||
	    !hmac_ctx.update(user_in, user_len) ||
	    !hmac_ctx.update(domain_in, domain_len) ||
	    !hmac_ctx.finish(kr))
		return false;

	hmac_ctx = HMACMD5_CTX(kr, 16);
	if (!hmac_ctx.is_valid() ||
	    !hmac_ctx.update(psec_blob->pb, psec_blob->cb) ||
	    !hmac_ctx.update(client_key.pb, client_key.cb) ||
	    !hmac_ctx.finish(value_from_encryption))
		return false;

	hmac_ctx = HMACMD5_CTX(kr, 16);
	if (!hmac_ctx.is_valid() ||
	    !hmac_ctx.update(value_from_encryption, 16) ||
	    !hmac_ctx.finish(puser_key->pb))
		return false;
	puser_key->cb = 16;
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
	
	gx_strlcpy(upper_domain, pntlmssp->domain, std::size(upper_domain));
	HX_strupper(upper_domain);
	uint8_t nt_p16[16]{}, p16[16]{};
	if (!ntlmssp_md4hash(plain_passwd, nt_p16) ||
	    !ntlmssp_deshash(plain_passwd, p16))
		return false;
	
	if (pnt_response->cb != 0 && pnt_response->cb < 24)
		mlog(LV_DEBUG, "ntlmssp: invalid NT password length (%u) for user %s "
			"in server_chkpasswd", pnt_response->cb, pntlmssp->user);

	if (pnt_response->cb > 24) {
		/* We have the NT MD4 hash challenge available - see if we can use it*/
		if (ntlmssp_check_ntlm2(pnt_response, nt_p16, pchallenge,
		    pntlmssp->user, pntlmssp->domain, puser_key) ||
		    ntlmssp_check_ntlm2(pnt_response, nt_p16, pchallenge,
		    pntlmssp->user, upper_domain, puser_key) ||
		    ntlmssp_check_ntlm2(pnt_response, nt_p16, pchallenge,
		    pntlmssp->user, "", puser_key)) {
			if (puser_key->cb > 8) {
				memcpy(plm_key->pb, puser_key->pb, 8);
				plm_key->cb = 8;
			} else {
				memcpy(plm_key->pb, puser_key->pb, puser_key->cb);
				plm_key->cb = puser_key->cb;
			}
			return true;
		}
	} else if (pnt_response->cb == 24) {
		if (ntlmssp_check_ntlm1(pnt_response, nt_p16,
		    pchallenge, puser_key)) {
			/* The LM session key for this response is not very secure, 
			   so use it only if we otherwise allow LM authentication */
			if (puser_key->cb > 8) {
				memcpy(plm_key->pb, p16, 8);
				plm_key->cb = 8;
			} else {
				memcpy(plm_key->pb, p16, puser_key->cb);
				plm_key->cb = puser_key->cb;
			}
			return true;
		}
		return false;
	} 
	
	if (plm_response->cb == 0) {
		mlog(LV_DEBUG, "ntlmssp: neither LanMan nor NT password supplied for "
			"user %s in server_chkpasswd", pntlmssp->user);
		return false;
	}
	if (plm_response->cb < 24) {
		mlog(LV_DEBUG, "ntlmssp: invalid LanMan password length (%u) for "
			"user %s in server_chkpasswd", pnt_response->cb, pntlmssp->user);
		return false;
	}
	if (ntlmssp_check_ntlm1(plm_response, p16, pchallenge, nullptr)) {
		memset(puser_key->pb, 0, 16);
		memcpy(puser_key->pb, p16, 8);
		puser_key->cb = 16;
		memcpy(plm_key->pb, p16, 8);
		plm_key->cb = 8;
		return true;
	}

	tmp_key.pb = tmp_key_buff;
	tmp_key.cb = 0;
	bool b_result = false;
	/* This is for 'LMv2' authentication.  almost NTLMv2 but limited to 24 bytes. */
	if (ntlmssp_check_ntlm2(plm_response, nt_p16, pchallenge,
	    pntlmssp->user, pntlmssp->domain, &tmp_key)) {
		b_result = true;
		pdomain = pntlmssp->domain;
	} else if (ntlmssp_check_ntlm2(plm_response, nt_p16, pchallenge,
	    pntlmssp->user, upper_domain, &tmp_key)) {
		b_result = true;
		pdomain = upper_domain;
	} else if (ntlmssp_check_ntlm2(plm_response, nt_p16, pchallenge,
	    pntlmssp->user, "", &tmp_key)) {
		b_result = true;
		pdomain = "";
	}
	
	if (b_result) {
		if (pnt_response->cb > 24) {
			ntlmssp_sess_key_ntlm2(pnt_response, nt_p16, pchallenge, 
				pntlmssp->user, pdomain, puser_key);
		} else {
			/* Otherwise, use the LMv2 session key */
			memcpy(puser_key->pb, tmp_key.pb, tmp_key.cb);
			puser_key->cb = tmp_key.cb;
		}
		if (puser_key->cb != 0) {
			if (puser_key->cb > 8) {
				memcpy(plm_key->pb, puser_key->pb, 8);
				plm_key->cb = 8;
			} else {
				memcpy(plm_key->pb, puser_key->pb, puser_key->cb);
				plm_key->cb = puser_key->cb;
			}
		}
		return true;
	}

	
	if (ntlmssp_check_ntlm1(plm_response, nt_p16, pchallenge, nullptr)) {
		/* The session key for this response is still very odd.  
		   It not very secure, so use it only if we otherwise 
		   allow LM authentication */	
			
		memset(puser_key->pb, 0, 16);
		memcpy(puser_key->pb, p16, 8);
		puser_key->cb = 16;
		memcpy(plm_key->pb, p16, 8);
		plm_key->cb = 8;
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
	
	if (pntlmssp->session_key.cb < 8) {
		mlog(LV_DEBUG, "ntlmssp: NO session key, cannot initialise "
			"signing in sign_init");
		return false;
	}
	memset(&pntlmssp->crypt, 0, sizeof(NTLMSSP_CRYPT_STATE));
	
	if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		weak_key = pntlmssp->session_key;
		send_seal_blob.pb = send_seal_buff;
		send_seal_blob.cb = sizeof(send_seal_buff);
		recv_seal_blob.pb = recv_seal_buff;
		recv_seal_blob.cb = sizeof(recv_seal_buff);
		send_sign_const = SRV_SIGN;
		send_seal_const = SRV_SEAL;
		recv_sign_const = CLI_SIGN;
		recv_seal_const = CLI_SEAL;

		if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_128)
			/* do nothing */;
		else if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_56)
			weak_key.cb = 7;
		else /* forty bits */
			weak_key.cb = 5;
		
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
		
		if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_LM_KEY)
			do_weak = true;
		if (seal_key.cb < 16)
			/* TODO: is this really correct? */
			do_weak = false;
		if (do_weak) {
			memcpy(weak_session_buff, seal_key.pb, 8);
			seal_key.pb = weak_session_buff;
			seal_key.cb = 8;
			if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_56) {
				weak_session_buff[7] = 0xa0;
			} else { /* forty bits */
				weak_session_buff[5] = 0xe5;
				weak_session_buff[6] = 0x38;
				weak_session_buff[7] = 0xb0;
			}
		}

		arcfour_init(&pntlmssp->crypt.ntlm.seal_state,
		             seal_key.pb, seal_key.cb);
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
	session_key.pb = session_key_buff;
	session_key.cb = 0;
	
	/* Handle the different session key derivation for NTLM2 */
	if (pauth->doing_ntlm2) {
		if (puser_key->cb == 16) {
			HMACMD5_CTX hmac_ctx(puser_key->pb, 16);
			if (!hmac_ctx.is_valid() ||
			    !hmac_ctx.update(pauth->session_nonce, sizeof(pauth->session_nonce)) ||
			    !hmac_ctx.finish(session_key.pb))
				return false;
			session_key.cb = 16;
		} else {
			session_key.cb = 0;
		}
	} else if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_LM_KEY && 
	    (pntlmssp->nt_resp.cb == 0 || pntlmssp->nt_resp.cb == 24)) {
		if (plm_key->cb >= 8) {
			if (pntlmssp->lm_resp.cb == 24)
				ntlmssp_lm_session_key(plm_key->pb, pntlmssp->lm_resp.pb,
					session_key.pb);
			else
				ntlmssp_lm_session_key(zeros, zeros, session_key.pb);
			session_key.cb = 16;
		} else {
			/* LM Key not selected */
			pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
			session_key.cb = 0;
		}
	} else if (puser_key->cb > 0) {
		memcpy(session_key.pb, puser_key->pb, puser_key->cb);
		session_key.cb = puser_key->cb;
		/* LM Key not selected */
		pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
	} else if (plm_key->cb > 0) {
		/* Very weird to have LM key, but no user session key, but anyway.. */
		memcpy(session_key.pb, plm_key->pb, plm_key->cb);
		session_key.cb = plm_key->cb;
		/* LM Key not selected */
		pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
	} else {
		session_key.cb = 0;
		/* LM Key not selected */
		pntlmssp->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
	}

	/* With KEY_EXCH, the client supplies the proposed session key,
	   but encrypts it with the long-term key */
	if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
		if (pauth->encrypted_session_key.cb != 16) {
			return false;
		} else if (session_key.cb != 16) {
			memcpy(pntlmssp->session_key.pb, session_key.pb,
				session_key.cb);
			pntlmssp->session_key.cb = session_key.cb;
		} else {
			arcfour_crypt(pauth->encrypted_session_key.pb, session_key.pb,
				pauth->encrypted_session_key.cb);
			memcpy(pntlmssp->session_key.pb, pauth->encrypted_session_key.pb,
				pauth->encrypted_session_key.cb);
			pntlmssp->session_key.cb = pauth->encrypted_session_key.cb;
		}
	} else {
		memcpy(pntlmssp->session_key.pb, session_key.pb, session_key.cb);
		pntlmssp->session_key.cb = session_key.cb;
	}
	if (pntlmssp->session_key.cb != 0)
		ntlmssp_sign_init(pntlmssp);
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
	pout->cb = 0;
	memset(&auth_state, 0, sizeof(NTLMSSP_SERVER_AUTH_STATE));
	if (!ntlmssp_server_preauth(pntlmssp, &auth_state, in))
		return false;
	auth_state.user_session_key.pb = auth_state.user_session_key_buff;
	auth_state.user_session_key.cb = 0;
	auth_state.lm_session_key.pb = auth_state.lm_session_key_buff;
	auth_state.lm_session_key.cb = 0;
	
	if (strchr(pntlmssp->user, '@') == nullptr)
			snprintf(username, std::size(username), "%s@%s",
			         pntlmssp->user, pntlmssp->domain);
	else
			gx_strlcpy(username, pntlmssp->user, std::size(username));
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

	if (pntlmssp->expected_state == NTLMSSP_PROCESS_DONE)
		return false;
	if (pblob->cb == 0)
		return false;
	if (!ntlmssp_parse_packet(*pblob, "Cd", "NTLMSSP", &ntlmssp_command))
		return false;
	if (ntlmssp_command != pntlmssp->expected_state) {
		mlog(LV_DEBUG, "ntlmssp: got NTLMSSP command %u, expected %u "
			"in ntlmssp_update", ntlmssp_command, pntlmssp->expected_state);
		return false;
	}
	
	tmp_blob.pb = blob_buff;
	tmp_blob.cb = 0;
	
	if (NTLMSSP_PROCESS_NEGOTIATE == ntlmssp_command) {
		if (!ntlmssp_server_negotiate(pntlmssp, *pblob, &tmp_blob))
			return false;
	} else if (NTLMSSP_PROCESS_AUTH == ntlmssp_command) {
		if (!ntlmssp_server_auth(pntlmssp, *pblob, &tmp_blob))
			return false;
	} else {
		mlog(LV_DEBUG, "ntlmssp: unexpected NTLMSSP command %u "
			"in ntlmssp_update", ntlmssp_command);
		return false;
	}
	
	free(pblob->pb);
	if (tmp_blob.cb == 0) {
		pblob->pb = nullptr;
	} else {
		pblob->pb = me_alloc<uint8_t>(tmp_blob.cb);
		if (pblob->pb == nullptr)
			return false;
		memcpy(pblob->pb, tmp_blob.pb, tmp_blob.cb);
	}
	pblob->cb = tmp_blob.cb;
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
			&psig->pb[4], psig->cb - 4);
		return true;
	}

	HMACMD5_CTX hmac_ctx;
	switch (direction) {
	case NTLMSSP_DIRECTION_SEND:
		cpu_to_le32p(seq_num, pntlmssp->crypt.ntlm2.sending.seq_num++);
		hmac_ctx = HMACMD5_CTX(pntlmssp->crypt.ntlm2.sending.sign_key, 16);
		break;
	case NTLMSSP_DIRECTION_RECEIVE:
		cpu_to_le32p(seq_num, pntlmssp->crypt.ntlm2.receiving.seq_num++);
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

	cpu_to_le32p(&psig->pb[0], NTLMSSP_SIGN_VERSION);
	memcpy(&psig->pb[4], digest, 8);
	memcpy(&psig->pb[12], seq_num, 4);
	psig->cb = NTLMSSP_SIG_SIZE;
	return true;
}

bool ntlmssp_sign_packet(NTLMSSP_CTX *pntlmssp, const uint8_t *pdata,
	size_t length, const uint8_t *pwhole_pdu, size_t pdu_length,
	DATA_BLOB *psig)
{
	std::lock_guard lk(pntlmssp->lock);
	if (!(pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_SIGN) ||
	    pntlmssp->session_key.cb == 0)
		return false;
	if (!ntlmssp_make_packet_signature(pntlmssp, pdata, length, pwhole_pdu,
	    pdu_length, NTLMSSP_DIRECTION_SEND, psig, true))
		return false;
	return true;
}

static bool ntlmssp_check_packet_internal(NTLMSSP_CTX *pntlmssp,
	const uint8_t *pdata, size_t length, const uint8_t *pwhole_pdu,
	size_t pdu_length, const DATA_BLOB *psig)
{
	DATA_BLOB local_sig;
	uint8_t local_sig_buff[16];
	
	local_sig.pb = local_sig_buff;
	if (pntlmssp->session_key.cb == 0)
		return false;
	if (pntlmssp->session_key.cb == 0) {
		mlog(LV_DEBUG, "ntlm: no session key, cannot check packet signature");
		return false;
	}
	if (psig->cb < 8)
		mlog(LV_DEBUG, "ntlmssp: NTLMSSP packet check failed due to short "
			"signature (%u bytes)! in check_packet", psig->cb);
	if (!ntlmssp_make_packet_signature(pntlmssp, pdata, length, pwhole_pdu,
	    pdu_length, NTLMSSP_DIRECTION_RECEIVE, &local_sig, true))
		return false;

	if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		if (local_sig.cb != psig->cb ||
			memcmp(local_sig.pb, psig->pb, psig->cb) != 0) {
			mlog(LV_DEBUG, "ntlmssp: NTLMSSP NTLM2 packet check failed due to invalid signature!");
			return false;
		}
	} else {
		if (local_sig.cb != psig->cb || memcmp(&local_sig.pb[8],
		    &psig->pb[8], psig->cb - 8) != 0) {
			mlog(LV_DEBUG, "ntlmssp: NTLMSSP NTLM1 packet check failed due to invalid signature!");
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
	    pdu_length, psig))
		return false;
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
	if (pntlmssp->session_key.cb == 0) {
		mlog(LV_DEBUG, "ntlm: no session key, cannot seal packet");
		return false;
	}
	if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		if (!ntlmssp_make_packet_signature(pntlmssp, pdata, length,
		    pwhole_pdu, pdu_length, NTLMSSP_DIRECTION_SEND, psig, false))
			return false;
		arcfour_crypt_sbox(&pntlmssp->crypt.ntlm2.sending.seal_state,
			pdata, length);
		if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH)
			arcfour_crypt_sbox(&pntlmssp->crypt.ntlm2.sending.seal_state,
				&psig->pb[4], 8);
	} else {
		crc = crc32_calc_buffer(pdata, length);
		if (!ntlmssp_gen_packet(psig, "dddd", NTLMSSP_SIGN_VERSION,
		    0, crc, pntlmssp->crypt.ntlm.seq_num))
			return false;
		arcfour_crypt_sbox(&pntlmssp->crypt.ntlm.seal_state, pdata, length);
		arcfour_crypt_sbox(&pntlmssp->crypt.ntlm.seal_state,
			&psig->pb[4], psig->cb - 4);
		pntlmssp->crypt.ntlm.seq_num ++;
	}
	return true;
}
	
bool ntlmssp_unseal_packet(NTLMSSP_CTX *pntlmssp, uint8_t *pdata,
	size_t length, const uint8_t *pwhole_pdu, size_t pdu_length,
	const DATA_BLOB *psig)
{
	std::lock_guard lk(pntlmssp->lock);
	if (pntlmssp->session_key.cb == 0) {
		mlog(LV_DEBUG, "ntlm: no session key, cannot unseal packet");
		return false;
	}
	if (pntlmssp->neg_flags & NTLMSSP_NEGOTIATE_NTLM2)
		/* First unseal the data. */
		arcfour_crypt_sbox(&pntlmssp->crypt.ntlm2.receiving.seal_state,
			pdata, length);
	else
		arcfour_crypt_sbox(&pntlmssp->crypt.ntlm.seal_state, pdata, length);
	if (!ntlmssp_check_packet_internal(pntlmssp, pdata, length, pwhole_pdu,
	    pdu_length, psig))
		return false;
	return true;
}

static bool ntlmssp_session_key(NTLMSSP_CTX *pntlmssp, DATA_BLOB *psession_key)
{
	if (pntlmssp->expected_state != NTLMSSP_PROCESS_DONE)
		return false;
	if (pntlmssp->session_key.cb == 0)
		return false;
	memcpy(psession_key->pb, pntlmssp->session_key.pb,
		pntlmssp->session_key.cb);
	psession_key->cb = pntlmssp->session_key.cb;
	return true;
}

bool ntlmssp_session_info(NTLMSSP_CTX *pntlmssp, NTLMSSP_SESSION_INFO *psession)
{
	if (strchr(pntlmssp->user, '@') == nullptr)
		snprintf(psession->username, std::size(psession->username),
		         "%s@%s", pntlmssp->user, pntlmssp->domain);
	else
		gx_strlcpy(psession->username, pntlmssp->user, std::size(psession->username));
	psession->session_key.pb = psession->session_key_buff;
	return ntlmssp_session_key(pntlmssp, &psession->session_key);
}

void ntlmssp_destroy(NTLMSSP_CTX *pntlmssp)
{
	delete pntlmssp;
}
