// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <gromox/binhex.hpp>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/util.hpp>
#define HEADERMATCH					40
#define MAXLINELEN					64

#define	GROWING_BLOCK_SIZE			64*1024

using namespace gromox;

namespace {
struct READ_STAT {
	uint8_t *pbuff = nullptr;
	uint32_t length = 0, offset = 0;
	uint16_t crc = 0;
	int state86 = 0, lastch = -1;
	uint8_t runlen = 0;
};

struct BINHEX_STREAM {
	uint8_t *data;
	uint32_t alloc_size;
	uint32_t offset;
};

struct WRITE_STAT {
	BINHEX_STREAM stream;
	char line[MAXLINELEN];
	uint8_t linelen;
	uint16_t crc;
	int state86;
	uint8_t runlen;
	uint8_t lastch;
};
}

static constexpr char g_hqxheader[] = "(This file must be converted with BinHex 4.0)\r\n";

static const int8_t g_demap[256] = {
   0,  0,  0,  0,  0,  0,  0,  0,
   0, -1, -1,  0,  0, -1,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,
  -1,  1,  2,  3,  4,  5,  6,  7,
   8,  9, 10, 11, 12, 13,  0,  0,
  14, 15, 16, 17, 18, 19, 20,  0,
  21, 22,  0,  0,  0,  0,  0,  0,
  23, 24, 25, 26, 27, 28, 29, 30,
  31, 32, 33, 34, 35, 36, 37,  0,
  38, 39, 40, 41, 42, 43, 44,  0,
  45, 46, 47, 48,  0,  0,  0,  0,
  49, 50, 51, 52, 53, 54, 55,  0,
  56, 57, 58, 59, 60, 61,  0,  0,
  62, 63, 64,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0
};

static const uint16_t g_magic[256] = {
  0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
  0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
  0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
  0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,

  0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
  0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
  0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
  0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,

  0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
  0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
  0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
  0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,

  0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
  0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
  0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
  0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,

  0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
  0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
  0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
  0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,

  0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
  0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
  0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
  0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,

  0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
  0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
  0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
  0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,

  0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
  0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
  0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
  0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
};

static constexpr uint8_t g_zero[2]{};

static uint16_t binhex_crc(const uint8_t *ptr,
	uint32_t count, uint16_t crc)
{
	while (count --) {
		crc = ((crc << 8) | *ptr++) ^ g_magic[crc >> 8];
	}
	return crc;
}

static bool binhex_init_read_stat(READ_STAT *pstat,
    void *pbuff, uint32_t length)
{
	pstat->pbuff = static_cast<uint8_t *>(pbuff);
	pstat->length = length;
	auto ptr = memmem(pbuff, length, g_hqxheader, HEADERMATCH);
	if (NULL == ptr) {
		mlog(LV_DEBUG, "binhex: hqx buffer header not found");
		return false;
	}
	for (pstat->offset = static_cast<char *>(ptr) - static_cast<char *>(pbuff) + HEADERMATCH;
		pstat->offset<length; pstat->offset++) {
		if ('\r' == pstat->pbuff[pstat->offset] ||
			'\n' == pstat->pbuff[pstat->offset]) {
			break;
		}
	}
	if (pstat->offset >= length) {
		mlog(LV_DEBUG, "binhex: corrupt hqx buffer");
		return false;
	}
	for (;pstat->offset<length; pstat->offset++) {
		if ('\r' != pstat->pbuff[pstat->offset] &&
			'\n' != pstat->pbuff[pstat->offset] &&
			'\t' != pstat->pbuff[pstat->offset] &&
			' ' != pstat->pbuff[pstat->offset]) {
			break;
		}
	}
	if (pstat->offset >= length) {
		mlog(LV_DEBUG, "binhex: corrupt hqx buffer");
		return false;
	}
	if (':' != pstat->pbuff[pstat->offset]) {
		mlog(LV_DEBUG, "binhex: corrupt hqx buffer");
		return false;
	}
	pstat->offset ++;
	return true;
}

static bool binhex_read_char(READ_STAT *pstat, uint8_t *pchar)
{
	uint8_t c = '\0';
	
	while (pstat->offset < pstat->length) {
		c = pstat->pbuff[pstat->offset++];
		if ('\r' != c && '\n' != c && '\t' != c && ' ' != c) {
			break;
		}
	}
	if (pstat->offset >= pstat->length) {
		mlog(LV_DEBUG, "binhex: unexpected end of hqx buffer");
		return false;
	}
	c = g_demap[c];
	if (0 == c) {
		mlog(LV_DEBUG, "binhex: illegal character in hqx buffer");
		return false;
	}
	*pchar = c - 1;
	return true;
}

static bool binhex_decode_char(READ_STAT *pstat, uint8_t *pb)
{
	uint8_t c, c2, ch = '\0';

	if (!binhex_read_char(pstat, &c))
		return false;
	switch (pstat->state86 & 0xFF00) {
	case 0x0000:
		if (!binhex_read_char(pstat, &c2))
			return false;
		ch = (c << 2) | (c2 >> 4);
		pstat->state86 = 0x0100 | (c2 & 0x0F);
		break;
	case 0x0100:
		ch = ((pstat->state86 & 0x0F) << 4) | (c >> 2);
		pstat->state86 = 0x0200 | (c & 0x03);
		break;
	case 0x0200:
		ch = ((pstat->state86 & 0x03) << 6) | c;
		pstat->state86 = 0;
		break;
	}
	*pb = ch;
	return true;
}

static bool binhex_read_buffer(READ_STAT *pstat, void *pbuff, uint32_t len)
{
	uint32_t i;
	uint8_t c, rl;
	
	auto ptr = static_cast<uint8_t *>(pbuff);
	for (i=0; i<len; i++) {
		if (0 != pstat->runlen) {
			*ptr++ = pstat->lastch;
			pstat->runlen --;
			continue;
		}
		if (!binhex_decode_char(pstat, &c))
			return false;
		if (0x90 == c) {
			if (!binhex_decode_char(pstat, &rl))
				return false;
			if (rl > 0) {
				if (pstat->lastch < 0)
					/* Cannot repeat without prior byte */
					return false;
				pstat->runlen = rl - 1;
				i --;
				continue;
			}
		}
		pstat->lastch = c;
		*ptr++ = c;
	}
	pstat->crc = binhex_crc(static_cast<uint8_t *>(pbuff), len, pstat->crc);
	return true;
}

static bool binhex_read_crc(READ_STAT *pstat)
{
	uint16_t check;
	uint8_t tmp_buff[2];

	check = binhex_crc(g_zero, 2, pstat->crc);
	if (!binhex_read_buffer(pstat, tmp_buff, 2))
		return false;
	pstat->crc = be16p_to_cpu(tmp_buff);
	if (pstat->crc != check) {
		mlog(LV_DEBUG, "binhex: CRC checksum error");
	}
	pstat->crc = 0;
	return true;
}

bool binhex_deserialize(BINHEX *pbinhex, void *pbuff, uint32_t length)
{
	uint8_t tmp_byte;
	uint8_t tmp_buff[4];
	READ_STAT read_stat;
	
	if (!binhex_init_read_stat(&read_stat, pbuff, length))
		return false;
	if (!binhex_read_buffer(&read_stat, &tmp_byte, 1))
		return false;
	if (tmp_byte > 63) {
		return false;
	}
	if (!binhex_read_buffer(&read_stat, pbinhex->file_name, tmp_byte + 1))
		return false;
	if (!binhex_read_buffer(&read_stat, &pbinhex->type, 4))
		return false;
	if (!binhex_read_buffer(&read_stat, &pbinhex->creator, 4))
		return false;
	if (!binhex_read_buffer(&read_stat, tmp_buff, 2))
		return false;
	pbinhex->flags = be16p_to_cpu(tmp_buff);
	if (!binhex_read_buffer(&read_stat, tmp_buff, 4))
		return false;
	pbinhex->data_len = be32p_to_cpu(tmp_buff);
	if (pbinhex->data_len >= length) {
		return false;
	}
	if (!binhex_read_buffer(&read_stat, tmp_buff, 4))
		return false;
	pbinhex->res_len = be32p_to_cpu(tmp_buff);
	if (pbinhex->res_len >= length) {
		return false;
	}
	if (!binhex_read_crc(&read_stat))
		return false;
	if (0 == pbinhex->data_len) {
		pbinhex->pdata = NULL;
	} else {
		pbinhex->pdata = me_alloc<uint8_t>(pbinhex->data_len);
		if (NULL == pbinhex->pdata) {
			pbinhex->data_len = 0;
			return false;
		}
	}
	if (0 == pbinhex->res_len) {
		pbinhex->presource = NULL;
	} else {
		pbinhex->presource = me_alloc<uint8_t>(pbinhex->res_len);
		if (NULL == pbinhex->presource) {
			pbinhex->res_len = 0;
			free(pbinhex->pdata);
			return false;
		}
	}
	if (NULL != pbinhex->pdata) {
		if (!binhex_read_buffer(&read_stat, pbinhex->pdata, pbinhex->data_len)) {
			free(pbinhex->pdata);
			free(pbinhex->presource);
			return false;
		}
	}
	if (!binhex_read_crc(&read_stat))
		return false;
	if (NULL != pbinhex->presource) {
		if (!binhex_read_buffer(&read_stat, pbinhex->presource, pbinhex->res_len)) {
			free(pbinhex->pdata);
			free(pbinhex->presource);
			return false;
		}
	}
	return binhex_read_crc(&read_stat);
}

void binhex_clear(BINHEX *pbinhex)
{
	if (NULL != pbinhex->pdata) {
		free(pbinhex->pdata);
	}
	if (NULL != pbinhex->presource) {
		free(pbinhex->presource);
	}
}
