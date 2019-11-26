#include "util.h"
#include "binhex.h"
#include "endian_macro.h"
#include <string.h>
#include <stdlib.h>

#define HEADERMATCH					40
#define MAXLINELEN					64

#define	GROWING_BLOCK_SIZE			64*1024

typedef struct _READ_STAT {
	uint8_t *pbuff;
	uint32_t length;
	uint32_t offset;
	uint16_t crc;
	int state86;
	uint8_t runlen;
	uint8_t lastch;
} READ_STAT;

typedef struct _BINHEX_STREAM {
	uint8_t *data;
	uint32_t alloc_size;
	uint32_t offset;
} BINHEXT_STREAM;

typedef struct _WRITE_STAT {
	BINHEXT_STREAM stream;
	char line[MAXLINELEN];
	uint8_t linelen;
	uint16_t crc;
	int state86;
	uint8_t runlen;
	uint8_t lastch;
} WRITE_STAT;


static char g_hqxheader[] = "(This file must be converted with BinHex 4.0)\r\n";

static uint8_t g_enmap[] = "!\"#$%&'()*+,-012345689@ABCDEFGHI"
							"JKLMNPQRSTUVXYZ[`abcdefhijklmpqr";

static const char g_demap[256] = {
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

static uint8_t g_zero[2] = {0, 0};

static uint16_t binhex_crc(const uint8_t *ptr,
	uint32_t count, uint16_t crc)
{
	while (count --) {
		crc = ((crc << 8) | *ptr) ^ g_magic[crc >> 8];
		ptr ++;
	}
	return crc;
}

static BOOL binhex_init_read_stat(READ_STAT *pstat,
	void *pbuff, uint32_t length)
{
	void *ptr;
	
	pstat->pbuff = pbuff;
	pstat->length = length;
	pstat->offset = 0;
	pstat->state86 = 0;
	pstat->runlen = 0;
	pstat->crc = 0;
	ptr = memmem(pbuff, length, g_hqxheader, HEADERMATCH);
	if (NULL == ptr) {
		debug_info("[binhex]: hqx buffer header not found");
		return FALSE;
	}
	for (pstat->offset=ptr-pbuff+HEADERMATCH;
		pstat->offset<length; pstat->offset++) {
		if ('\r' == pstat->pbuff[pstat->offset] ||
			'\n' == pstat->pbuff[pstat->offset]) {
			break;
		}
	}
	if (pstat->offset >= length) {
		debug_info("[binhex]: corrupt hqx buffer");
		return FALSE;
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
		debug_info("[binhex]: corrupt hqx buffer");
		return FALSE;
	}
	if (':' != pstat->pbuff[pstat->offset]) {
		debug_info("[binhex]: corrupt hqx buffer");
		return FALSE;
	}
	pstat->offset ++;
	return TRUE;
}

static BOOL binhex_read_char(READ_STAT *pstat, uint8_t *pchar)
{
	uint8_t c;
	
	while (pstat->offset < pstat->length) {
		c = pstat->pbuff[pstat->offset];
		pstat->offset ++;
		if ('\r' != c && '\n' != c && '\t' != c && ' ' != c) {
			break;
		}
	}
	if (pstat->offset >= pstat->length) {
		debug_info("[binhex]: unexpected end of hqx buffer");
		return FALSE;
	}
	c = g_demap[c];
	if (0 == c) {
		debug_info("[binhex]: illegal character in hqx buffer");
		return FALSE;
	}
	*pchar = c - 1;
	return TRUE;
}

static BOOL binhex_decode_char(READ_STAT *pstat, uint8_t *pb)
{
	uint8_t c, c2, ch;

	if (FALSE == binhex_read_char(pstat, &c)) {
		return FALSE;
	}
	switch (pstat->state86 & 0xFF00) {
	case 0x0000:
		if (FALSE == binhex_read_char(pstat, &c2)) {
			return FALSE;
		}
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
	return TRUE;
}

static BOOL binhex_read_buffer(
	READ_STAT *pstat, void *pbuff, uint32_t len)
{
	uint32_t i;
	uint8_t *ptr;
	uint8_t c, rl;
	
	ptr = pbuff;
	for (i=0; i<len; i++) {
		if (0 != pstat->runlen) {
			*ptr = pstat->lastch;
			ptr ++;
			pstat->runlen --;
			continue;
		}
		if (FALSE == binhex_decode_char(pstat, &c)) {
			return FALSE;
		}
		if (0x90 == c) {
			if (FALSE == binhex_decode_char(pstat, &rl)) {
				return FALSE;
			}
			if (rl > 0) {
				pstat->runlen = rl - 1;
				i --;
				continue;
			}
		}
		pstat->lastch = c;
		*ptr = c;
		ptr ++;
	}
	pstat->crc = binhex_crc(pbuff, len, pstat->crc);
	return TRUE;
}

static BOOL binhex_read_crc(READ_STAT *pstat)
{
	uint16_t check;
	uint8_t tmp_buff[2];

	check = binhex_crc(g_zero, 2, pstat->crc);
	if (FALSE == binhex_read_buffer(pstat, tmp_buff, 2)) {
		return FALSE;
	}
	pstat->crc = RSVAL(tmp_buff, 0);
	if (pstat->crc != check) {
		debug_info("[binhex]: CRC checksum error");
	}
	pstat->crc = 0;
	return TRUE;
}

BOOL binhex_deserialize(BINHEX *pbinhex,
	void *pbuff, uint32_t length)
{
	uint8_t tmp_byte;
	uint8_t tmp_buff[4];
	READ_STAT read_stat;
	
	if (FALSE == binhex_init_read_stat(&read_stat, pbuff, length)) {
		return FALSE;
	}
	if (FALSE == binhex_read_buffer(&read_stat, &tmp_byte, 1)) {
		return FALSE;
	}
	if (tmp_byte > 63) {
		return FALSE;
	}
	if (FALSE == binhex_read_buffer(&read_stat,
		pbinhex->file_name, tmp_byte + 1)) {
		return FALSE;
	}
	if (FALSE == binhex_read_buffer(&read_stat, &pbinhex->type, 4)) {
		return FALSE;
	}
	if (FALSE == binhex_read_buffer(&read_stat, &pbinhex->creator, 4)) {
		return FALSE;
	}
	if (FALSE == binhex_read_buffer(&read_stat, tmp_buff, 2)) {
		return FALSE;
	}
	pbinhex->flags = RSVAL(tmp_buff, 0);
	if (FALSE == binhex_read_buffer(&read_stat, tmp_buff, 4)) {
		return FALSE;
	}
	pbinhex->data_len = RIVAL(tmp_buff, 0);
	if (pbinhex->data_len >= length) {
		return FALSE;
	}
	if (FALSE == binhex_read_buffer(&read_stat, tmp_buff, 4)) {
		return FALSE;
	}
	pbinhex->res_len = RIVAL(tmp_buff, 0);
	if (pbinhex->res_len >= length) {
		return FALSE;
	}
	if (FALSE == binhex_read_crc(&read_stat)) {
		return FALSE;
	}
	if (0 == pbinhex->data_len) {
		pbinhex->pdata = NULL;
	} else {
		pbinhex->pdata = malloc(pbinhex->data_len);
		if (NULL == pbinhex->pdata) {
			return FALSE;
		}
	}
	if (0 == pbinhex->res_len) {
		pbinhex->presource = NULL;
	} else {
		pbinhex->presource = malloc(pbinhex->res_len);
		if (NULL == pbinhex->presource) {
			free(pbinhex->pdata);
			return FALSE;
		}
	}
	if (NULL != pbinhex->pdata) {
		if (FALSE == binhex_read_buffer(&read_stat,
			pbinhex->pdata, pbinhex->data_len)) {
			free(pbinhex->pdata);
			free(pbinhex->presource);
			return FALSE;
		}
	}
	if (FALSE == binhex_read_crc(&read_stat)) {
		return FALSE;
	}
	if (NULL != pbinhex->presource) {
		if (FALSE == binhex_read_buffer(&read_stat,
			pbinhex->presource, pbinhex->res_len)) {
			free(pbinhex->pdata);
			free(pbinhex->presource);
			return FALSE;
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

static BOOL binhex_stream_init(BINHEXT_STREAM *pstream)
{
	pstream->alloc_size = GROWING_BLOCK_SIZE;
	pstream->data = malloc(GROWING_BLOCK_SIZE);
	if (NULL == pstream->data) {
		return FALSE;
	}
	pstream->offset = 0;
	return TRUE;
}

static BOOL binhex_stream_check_overflow(
	BINHEXT_STREAM *pstream, uint32_t extra_size)
{
	uint32_t size;
	uint8_t *pdata;
	uint32_t alloc_size;
	
	size = extra_size + pstream->offset;
	if (pstream->alloc_size >= size) {
		return TRUE;
	}
	for (alloc_size=pstream->alloc_size; alloc_size<size;
		alloc_size+=GROWING_BLOCK_SIZE);
	pdata = realloc(pstream->data, alloc_size);
	if (NULL == pdata) {
		free(pstream->data);
		return FALSE;
	}
	pstream->data = pdata;
	pstream->alloc_size = alloc_size;
	return TRUE;
}

static BOOL binhex_write_stream(BINHEXT_STREAM *pstream,
	const void *pdata, uint32_t n)
{
	if (FALSE == binhex_stream_check_overflow(pstream, n)) {
		return FALSE;
	}
	memcpy(pstream->data + pstream->offset, pdata, n);
	pstream->offset += n;
	return TRUE;
}

static BOOL binhex_init_write_stat(WRITE_STAT *pstat)
{
	void *ptr;
	
	if (FALSE == binhex_stream_init(&pstat->stream)) {
		return FALSE;
	}
	pstat->state86 = 0;
	pstat->runlen = 0;
	pstat->crc = 0;
	if (FALSE == binhex_write_stream(&pstat->stream,
		g_hqxheader, sizeof(g_hqxheader) - 1)) {
		return FALSE;
	}
	if (NULL == ptr) {
		debug_info("[binhex]: hqx buffer header not found");
		return FALSE;
	}
	pstat->line[0] = ':';
	pstat->linelen = 1;
	return TRUE;
}

static BOOL binhex_flush_line(WRITE_STAT *pstat)
{
	if (FALSE == binhex_write_stream(
		&pstat->stream, pstat->line, pstat->linelen)) {
		return FALSE;
	}
	if (FALSE == binhex_write_stream(&pstat->stream, "\r\n", 2)) {
		return FALSE;
	}
	pstat->linelen = 0;
	return TRUE;
}

static BOOL binhex_add_chars(WRITE_STAT *pstat,
	const uint8_t *pdata, uint32_t len)
{
	uint8_t c;

	while (len --) {
		c = *pdata;
		pdata ++;
		if (MAXLINELEN == pstat->linelen &&
			FALSE == binhex_flush_line(pstat)) {
			return FALSE;
		}
		switch (pstat->state86 & 0xFF00) {
		case 0x0000:
			pstat->line[pstat->linelen] = g_enmap[c >> 2];
			pstat->linelen ++;
			pstat->state86 = 0x0100 | (c & 0x03);
			break;
		case 0x0100:
			pstat->line[pstat->linelen] =
				g_enmap[((pstat->state86 & 0x03) << 4) | (c >> 4)];
			pstat->linelen ++;
			pstat->state86 = 0x0200 | (c & 0x0F);
			break;
		case 0x0200:
			pstat->line[pstat->linelen] =
				g_enmap[((pstat->state86 & 0x0F) << 2) | (c >> 6)];
			pstat->linelen ++;
			if (MAXLINELEN == pstat->linelen &&
				FALSE == binhex_flush_line(pstat)) {
				return FALSE;
			}
			pstat->line[pstat->linelen] = g_enmap[c & 0x3F];
			pstat->linelen ++;
			pstat->state86 = 0;
			break;
		}
	}
	return TRUE;
}


static BOOL binhex_runlen_flush(WRITE_STAT *pstat)
{
	uint8_t rle[] = {0x90, 0x00, 0x90, 0x00};

	if ((0x90 != pstat->lastch && pstat->runlen < 4) ||
		(0x90 == pstat->lastch && pstat->runlen < 3)) {
		if (0x90 == pstat->lastch) {
			while (pstat->runlen --) {
				if (FALSE == binhex_add_chars(
					pstat, rle, 2)) {
					return FALSE;
				}
			}
		} else {
			while (pstat->runlen --) {
				if (FALSE == binhex_add_chars(
					pstat, &pstat->lastch, 1)) {
					return FALSE;
				}
			}
		}
	} else {
		if (0x90 == pstat->lastch) {
			rle[3] = pstat->runlen;
			if (FALSE == binhex_add_chars(pstat, rle, 4)) {
				return FALSE;
			}
		} else {
			rle[1] = pstat->lastch;
			rle[3] = pstat->runlen;
			if (FALSE == binhex_add_chars(pstat, rle + 1, 3)) {
				return FALSE;
			}
		}
	}
	pstat->runlen = 0;
	return TRUE;
}

static BOOL binhex_write_buffer(WRITE_STAT *pstat,
	const void *pbuff, uint32_t len)
{
	const uint8_t *pdata;

	pdata = pbuff;
	pstat->crc = binhex_crc(pdata, len, pstat->crc);
	for (; len--; pdata++) {
		if (0 != pstat->runlen) {
			if (0xFF == pstat->runlen ||
				pstat->lastch != *pdata) {
				if (FALSE == binhex_runlen_flush(pstat)) {
					return FALSE;
				}
			}
		}
		if (pstat->lastch == *pdata) {
			pstat->runlen ++;
			continue;
		}
		pstat->lastch = *pdata;
		pstat->runlen = 1;
	}
	return TRUE;
}

static BOOL binhex_write_crc(WRITE_STAT *pstat)
{
	uint8_t word[2];

	pstat->crc = binhex_crc(g_zero, 2, pstat->crc);
	RSSVAL(word, 0, pstat->crc);
	if (FALSE == binhex_write_buffer(pstat, word, 2)) {
		return FALSE;
	}
	pstat->crc = 0;
	return TRUE;
}

BINARY* binhex_serialize(const BINHEX *pbinhex)
{
	int tmp_len;
	BINARY *pbin;
	uint8_t tmp_byte;
	uint8_t tmp_buff[4];
	WRITE_STAT write_stat;
	
	tmp_len = strlen(pbinhex->file_name);
	if (tmp_len > 63) {
		return FALSE;
	}
	if (FALSE == binhex_init_write_stat(&write_stat)) {
		return FALSE;
	}
	tmp_byte = tmp_len;
	if (FALSE == binhex_write_buffer(&write_stat, &tmp_byte, 1)) {
		return FALSE;
	}
	if (FALSE == binhex_write_buffer(&write_stat,
		pbinhex->file_name, tmp_byte + 1)) {
		return FALSE;
	}
	if (FALSE == binhex_write_buffer(&write_stat, &pbinhex->type, 4)) {
		return FALSE;
	}
	if (FALSE == binhex_write_buffer(&write_stat, &pbinhex->creator, 4)) {
		return FALSE;
	}
	RSSVAL(tmp_buff, 0, pbinhex->flags);
	if (FALSE == binhex_write_buffer(&write_stat, tmp_buff, 2)) {
		return FALSE;
	}
	RSIVAL(tmp_buff, 0, pbinhex->data_len);
	if (FALSE == binhex_write_buffer(&write_stat, tmp_buff, 4)) {
		return FALSE;
	}
	RSIVAL(tmp_buff, 0, pbinhex->res_len);
	if (FALSE == binhex_write_buffer(&write_stat, tmp_buff, 4)) {
		return FALSE;
	}
	if (FALSE == binhex_write_crc(&write_stat)) {
		return FALSE;
	}
	if (NULL != pbinhex->pdata) {
		if (FALSE == binhex_write_buffer(&write_stat,
			pbinhex->pdata, pbinhex->data_len)) {
			return FALSE;
		}
	}
	if (FALSE == binhex_write_crc(&write_stat)) {
		return FALSE;
	}
	if (NULL != pbinhex->presource) {
		if (FALSE == binhex_write_buffer(&write_stat,
			pbinhex->presource, pbinhex->res_len)) {
			return FALSE;
		}
	}
	if (FALSE == binhex_write_crc(&write_stat)) {
		return FALSE;
	}
	if (0 != write_stat.state86) {
		tmp_byte = 0;
		if (FALSE == binhex_write_buffer(&write_stat, &tmp_byte, 1)) {
			return FALSE;
		}
	}
	if (0 != write_stat.runlen) {
		if (FALSE == binhex_runlen_flush(&write_stat)) {
			return FALSE;
		}
	}
	if (MAXLINELEN == write_stat.linelen) {
		if (FALSE == binhex_flush_line(&write_stat)) {
			return FALSE;
		}
	}
	write_stat.line[write_stat.linelen] = ':';
	write_stat.linelen ++;
	if (FALSE == binhex_flush_line(&write_stat)) {
		return FALSE;
	}
	pbin = malloc(sizeof(BINARY));
	if (NULL == pbin) {
		free(write_stat.stream.data);
		return FALSE;
	}
	pbin->cb = write_stat.stream.offset;
	pbin->pb = write_stat.stream.data;
	return pbin;
}

