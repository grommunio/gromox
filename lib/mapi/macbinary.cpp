// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstring>
#include <libHX/string.h>
#include <gromox/endian.hpp>
#include <gromox/macbinary.hpp>
#include <gromox/util.hpp>
#define TRY(expr) do { pack_result klfdv{expr}; if (klfdv != EXT_ERR_SUCCESS) return klfdv; } while (false)
#define macbinary_push_int32(e, v) macbinary_push_uint32((e), (v))

/* Mac time of 00:00:00 GMT, Jan 1, 1970 */
#define TIMEDIFF 0x7c25b080

using namespace gromox;

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

static uint16_t macbinary_crc(const uint8_t *ptr,
	uint32_t count, uint16_t crc)
{
	while (count --) {
		crc ^= *ptr++ << 8;
		crc  = (crc << 8) ^ g_magic[crc >> 8];
	}
	return crc;
}

static pack_result macbinary_pull_uint16(EXT_PULL *pext, uint16_t *v)
{
	auto &ext = *pext;
	if (ext.m_data_size < sizeof(uint16_t) ||
	    ext.m_offset + sizeof(uint16_t) > ext.m_data_size)
		return EXT_ERR_BUFSIZE;
	memcpy(v, &ext.m_udata[ext.m_offset], sizeof(*v));
	*v = be16_to_cpu(*v);
	ext.m_offset += sizeof(uint16_t);
	return EXT_ERR_SUCCESS;
}

static pack_result macbinary_pull_uint32(EXT_PULL *pext, uint32_t *v)
{
	auto &ext = *pext;
	if (ext.m_data_size < sizeof(uint32_t) ||
	    ext.m_offset + sizeof(uint32_t) > ext.m_data_size)
		return EXT_ERR_BUFSIZE;
	memcpy(v, &ext.m_udata[ext.m_offset], sizeof(*v));
	*v = be32_to_cpu(*v);
	ext.m_offset += sizeof(uint32_t);
	return EXT_ERR_SUCCESS;
}

static pack_result macbinary_pull_int32(EXT_PULL *pext, int32_t *v)
{
	return macbinary_pull_uint32(pext, reinterpret_cast<uint32_t *>(v));
}

static pack_result macbinary_pull_header(EXT_PULL *pext, MACBINARY_HEADER *r)
{
	auto &ext = *pext;
	uint16_t crc;
	int32_t tmp_int;
	uint8_t tmp_byte;
	uint32_t offset = ext.m_offset;

	TRY(pext->g_uint8(&r->old_version));
	TRY(pext->g_uint8(&tmp_byte));
	if (tmp_byte > 63) {
		return EXT_ERR_FORMAT;
	}
	TRY(pext->g_bytes(r->file_name, tmp_byte));
	r->file_name[tmp_byte] = '\0';
	TRY(pext->advance(63 - tmp_byte));
	TRY(pext->g_bytes(&r->type, 4));
	TRY(pext->g_bytes(&r->creator, 4));
	TRY(pext->g_uint8(&r->original_flags));
	TRY(pext->g_uint8(&r->pad1));
	TRY(macbinary_pull_uint16(pext, &r->point_v));
	TRY(macbinary_pull_uint16(pext, &r->point_h));
	TRY(macbinary_pull_uint16(pext, &r->folder_id));
	TRY(pext->g_uint8(&r->protected_flag));
	TRY(pext->g_uint8(&r->pad2));
	TRY(macbinary_pull_uint32(pext, &r->data_len));
	TRY(macbinary_pull_uint32(pext, &r->res_len));
	TRY(macbinary_pull_int32(pext, &tmp_int));
	r->creat_time = TIMEDIFF + tmp_int;
	TRY(macbinary_pull_int32(pext, &tmp_int));
	r->modify_time = TIMEDIFF + tmp_int;
	TRY(macbinary_pull_uint16(pext, &r->comment_len));
	TRY(pext->g_uint8(&r->finder_flags));
	TRY(pext->g_bytes(reinterpret_cast<uint8_t *>(&r->signature), 4));
	TRY(pext->g_int8(&r->fd_script));
	TRY(pext->g_int8(&r->fd_xflags));
	TRY(pext->g_bytes(r->pads1, 8));
	TRY(macbinary_pull_uint32(pext, &r->total_unpacked));
	TRY(macbinary_pull_uint16(pext, &r->xheader_len));
	TRY(pext->g_uint8(&r->version));
	if (129 != r->version && 130 != r->version) {
		return EXT_ERR_FORMAT;
	}
	if (130 == r->version && 0 != strncmp(
		(char*)&r->signature, "mBIN", 4)) {
		mlog(LV_DEBUG, "macbinary: signature of MacBinaryIII error");
	}
	TRY(pext->g_uint8(&r->mini_version));
	if (129 != r->mini_version) {
		return EXT_ERR_FORMAT;
	}
	TRY(macbinary_pull_uint16(pext, &crc));
	if (macbinary_crc(&ext.m_udata[offset], 124, 0) != crc)
		mlog(LV_DEBUG, "macbinary: CRC checksum error");
	return pext->g_bytes(r->pads2, 2);
}

static pack_result macbinary_push_uint16(EXT_PUSH *pext, uint16_t v)
{
	auto &ext = *pext;
	if (!pext->check_ovf(sizeof(uint16_t)))
		return EXT_ERR_BUFSIZE;
	cpu_to_be16p(&ext.m_udata[ext.m_offset], v);
	ext.m_offset += sizeof(uint16_t);
	return EXT_ERR_SUCCESS;
}

static pack_result macbinary_push_uint32(EXT_PUSH *pext, uint32_t v)
{
	auto &ext = *pext;
	if (!pext->check_ovf(sizeof(uint32_t)))
		return EXT_ERR_BUFSIZE;
	cpu_to_be32p(&ext.m_udata[ext.m_offset], v);
	ext.m_offset += sizeof(uint32_t);
	return EXT_ERR_SUCCESS;
}

static pack_result macbinary_push_header(EXT_PUSH *pext, const MACBINARY_HEADER *r)
{
	auto &ext = *pext;
	int32_t tmp_int;
	uint8_t tmp_byte;
	
	uint32_t offset = ext.m_offset;
	TRY(pext->p_uint8(r->old_version));
	tmp_byte = strlen(r->file_name);
	if (tmp_byte > 63) {
		return EXT_ERR_FORMAT;
	}
	TRY(pext->p_uint8(tmp_byte));
	char newfile[64]{};
	gx_strlcpy(newfile, r->file_name, sizeof(newfile));
	TRY(pext->p_bytes(newfile, 63));
	TRY(pext->p_bytes(&r->type, 4));
	TRY(pext->p_bytes(&r->creator, 4));
	TRY(pext->p_uint8(r->original_flags));
	TRY(pext->p_uint8(r->pad1));
	TRY(macbinary_push_uint16(pext, r->point_v));
	TRY(macbinary_push_uint16(pext, r->point_h));
	TRY(macbinary_push_uint16(pext, r->folder_id));
	TRY(pext->p_uint8(r->protected_flag));
	TRY(pext->p_uint8(r->pad2));
	TRY(macbinary_push_uint32(pext, r->data_len));
	TRY(macbinary_push_uint32(pext, r->res_len));
	tmp_int = r->creat_time - TIMEDIFF;
	TRY(macbinary_push_int32(pext, tmp_int));
	tmp_int = r->modify_time - TIMEDIFF;
	TRY(macbinary_push_int32(pext, tmp_int));
	TRY(macbinary_push_uint16(pext, r->comment_len));
	TRY(pext->p_uint8(r->finder_flags));
	if (0 != strncmp((char*)&r->signature, "mBIN", 4)) {
		return EXT_ERR_FORMAT;
	}
	TRY(pext->p_bytes(&r->signature, 4));
	TRY(pext->p_int8(r->fd_script));
	TRY(pext->p_int8(r->fd_xflags));
	TRY(pext->p_bytes(r->pads1, 8));
	TRY(macbinary_push_uint32(pext, r->total_unpacked));
	TRY(macbinary_push_uint16(pext, r->xheader_len));
	if (130 != r->version) {
		return EXT_ERR_FORMAT;
	}
	TRY(pext->p_uint8(r->version));
	if (129 != r->mini_version) {
		return EXT_ERR_FORMAT;
	}
	TRY(pext->p_uint8(r->mini_version));
	uint16_t crc = macbinary_crc(&ext.m_udata[offset], 124, 0);
	TRY(macbinary_push_uint16(pext, crc));
	return pext->p_bytes(r->pads2, 2);
}

pack_result macbinary_pull_binary(EXT_PULL *pext, MACBINARY *r)
{
	auto &ext = *pext;
	TRY(macbinary_pull_header(pext, &r->header));
	if (0 != r->header.xheader_len) {
		ext.m_offset = (ext.m_offset + 127) & ~127;
		if (ext.m_offset > ext.m_data_size)
			return EXT_ERR_BUFSIZE;
		r->pxheader = &ext.m_udata[ext.m_offset];
		ext.m_offset += r->header.xheader_len;
	} else {
		r->pxheader = NULL;
	}
	if (0 != r->header.data_len) {
		ext.m_offset = (ext.m_offset + 127) & ~127;
		if (ext.m_offset > ext.m_data_size)
			return EXT_ERR_BUFSIZE;
		r->pdata = &ext.m_udata[ext.m_offset];
		ext.m_offset += r->header.data_len;
	} else {
		r->pdata = NULL;
	}
	if (0 != r->header.res_len) {
		ext.m_offset = (ext.m_offset + 127) & ~127;
		if (ext.m_offset > ext.m_data_size)
			return EXT_ERR_BUFSIZE;
		r->presource = &ext.m_udata[ext.m_offset];
		ext.m_offset += r->header.res_len;
	} else {
		r->presource = NULL;
	}
	if (0 != r->header.comment_len) {
		ext.m_offset = (ext.m_offset + 127) & ~127;
		if (ext.m_offset > ext.m_data_size)
			return EXT_ERR_BUFSIZE;
		r->pcomment = &ext.m_udata[ext.m_offset];
		ext.m_offset += r->header.comment_len;
	} else {
		r->pcomment = NULL;
	}
	return EXT_ERR_SUCCESS;
}

pack_result macbinary_push_binary(EXT_PUSH *pext, const MACBINARY *r)
{
	auto &ext = *pext;
	uint8_t pad_buff[128]{};
	
	TRY(macbinary_push_header(pext, &r->header));
	if (0 != r->header.xheader_len) {
		if (NULL == r->pxheader) {
			return EXT_ERR_FORMAT;
		}
		uint32_t pad_len = ((ext.m_offset + 127) & ~127) - ext.m_offset;
		TRY(pext->p_bytes(pad_buff, pad_len));
		TRY(pext->p_bytes(r->pxheader, r->header.xheader_len));
	}
	if (0 != r->header.data_len) {
		if (NULL == r->pdata) {
			return EXT_ERR_FORMAT;
		}
		uint32_t pad_len = ((ext.m_offset + 127) & ~127) - ext.m_offset;
		TRY(pext->p_bytes(pad_buff, pad_len));
		TRY(pext->p_bytes(r->pdata, r->header.data_len));
	}
	if (0 != r->header.res_len) {
		if (NULL == r->presource) {
			return EXT_ERR_FORMAT;
		}
		uint32_t pad_len = ((ext.m_offset + 127) & ~127) - ext.m_offset;
		TRY(pext->p_bytes(pad_buff, pad_len));
		TRY(pext->p_bytes(r->presource, r->header.res_len));
	}
	if (0 != r->header.comment_len) {
		if (NULL == r->pcomment) {
			return EXT_ERR_FORMAT;
		}
		uint32_t pad_len = ((ext.m_offset + 127) & ~127) - ext.m_offset;
		TRY(pext->p_bytes(pad_buff, pad_len));
		TRY(pext->p_bytes(r->pcomment, r->header.comment_len));
	}
	return EXT_ERR_SUCCESS;
}
