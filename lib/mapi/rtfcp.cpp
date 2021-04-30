// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#include <climits>
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <cstring>
#include <cstdlib>
#include <gromox/rtfcp.hpp>
#define	RTF_COMPRESSED			0x75465a4c
#define	RTF_UNCOMPRESSED		0x414c454d

/* initial length of dictionary */
#define RTF_INITLENGTH			207

#define	RTF_DICTLENGTH			0x1000
#define	RTF_HEADERLENGTH		0x10

/* initial directory */
#define RTF_INITDICT					\
  "{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}"	\
  "{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscrip"	\
  "t \\fdecor MS Sans SerifSymbolArialTimes Ne"		\
  "w RomanCourier{\\colortbl\\red0\\green0\\blue0"	\
  "\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab"	\
  "\\tx"

namespace {

/* header for compressed rtf */
struct COMPRESS_HEADER {
	uint32_t size;
	uint32_t rawsize;
	uint32_t magic;
	uint32_t crc;
};

struct DECOMPRESSION_STATE {
	uint8_t dict[RTF_DICTLENGTH];
	uint32_t dict_writeoffset;
	uint8_t *compressed_data;
	uint32_t in_size;
	uint32_t in_pos;
};

struct OUTPUT_STATE {
	uint32_t out_size;
	uint32_t out_pos;
	char *pbuff_out;
	size_t max_length;
};

struct DICTIONARYREF {
	uint8_t length;
	uint16_t offset;
};

}

static void rtfcp_init_decompress_state(uint8_t *compressed_data,
	uint32_t in_size, DECOMPRESSION_STATE *pstate)
{
	memcpy(pstate->dict, RTF_INITDICT, RTF_INITLENGTH);
	pstate->dict_writeoffset = RTF_INITLENGTH;
	pstate->compressed_data = compressed_data;
	pstate->in_size = in_size;
	pstate->in_pos = RTF_HEADERLENGTH;
}

static void rtfcp_init_output_state(OUTPUT_STATE *pstate,
	uint32_t rawsize, char *pbuff_out, size_t max_length)
{
	pstate->out_pos = 0;
	pstate->out_size = rawsize + RTF_HEADERLENGTH + 4;
	pstate->pbuff_out = pbuff_out;
	pstate->max_length = max_length;
}

static bool rtfcp_verify_header(uint8_t *header_data,
	uint32_t in_size, COMPRESS_HEADER *pheader)
{
	uint32_t enc4;
	memcpy(&enc4, &header_data[0], sizeof(enc4));
	pheader->size = le32_to_cpu(enc4);
	memcpy(&enc4, &header_data[4], sizeof(enc4));
	pheader->rawsize = le32_to_cpu(enc4);
	memcpy(&enc4, &header_data[8], sizeof(enc4));
	pheader->magic = le32_to_cpu(enc4);
	memcpy(&enc4, &header_data[12], sizeof(enc4));
	pheader->crc = le32_to_cpu(enc4);
	if (pheader->size != in_size - 4) {
		return false;
	}
	if (pheader->magic != RTF_COMPRESSED &&
		pheader->magic != RTF_UNCOMPRESSED) {
		return false;
	}
	return true;
}

static uint8_t rtfcp_get_next_byte(DECOMPRESSION_STATE *pstate)
{
	uint8_t next_byte;
	
	if (pstate->in_pos > pstate->in_size) {
		return 0;
	}  
	next_byte = pstate->compressed_data[pstate->in_pos];
	pstate->in_pos ++;
	return next_byte;
}

static uint8_t rtfcp_get_next_control(DECOMPRESSION_STATE *pstate)
{
	return rtfcp_get_next_byte(pstate);
}

static uint8_t rtf_get_next_literal(DECOMPRESSION_STATE *pstate)
{
	return rtfcp_get_next_byte(pstate);
}

static DICTIONARYREF rtfcp_get_next_dictionary_reference(
	DECOMPRESSION_STATE *pstate)
{
	uint8_t lowbyte;
	uint8_t highbyte;
	DICTIONARYREF reference;
	
	highbyte = rtfcp_get_next_byte(pstate);
	lowbyte = rtfcp_get_next_byte(pstate);
	reference.length = lowbyte & 0x0F;
	reference.length += 2;
	reference.offset = ((highbyte << 8) + lowbyte);
	reference.offset &= 0xFFF0;
	reference.offset >>= 4;
	return reference;
}

static void rtfcp_append_to_dictionary(
	DECOMPRESSION_STATE *pstate, char c)
{
	pstate->dict[pstate->dict_writeoffset] = c;
	pstate->dict_writeoffset =
		(pstate->dict_writeoffset + 1)%RTF_DICTLENGTH;
}

static void rtfcp_append_to_output(OUTPUT_STATE *poutput, char c)
{
	poutput->pbuff_out[poutput->out_pos] = c;
	poutput->out_pos ++;
}

static char rtfcp_get_dictionary_entry(
	DECOMPRESSION_STATE *pstate, uint32_t index)
{
	return pstate->dict[index%RTF_DICTLENGTH];
}

static bool rtfcp_check_output_overflow(OUTPUT_STATE *poutput)
{
	if (poutput->out_pos > poutput->out_size) {
		return false;
	}
	return true;
}

static bool rtfcp_check_input_overflow(DECOMPRESSION_STATE *state)
{
	if (state->in_pos > state->in_size) {
		return false;
	}
	return true;
}

bool rtfcp_uncompress(const BINARY *prtf_bin, char *pbuff_out, size_t *plength)
{
	int i;
	char c;
	uint8_t control;
	uint8_t bitmask_pos;
	OUTPUT_STATE output;
	DICTIONARYREF dictref;
	COMPRESS_HEADER header;
	DECOMPRESSION_STATE	state;

	if (prtf_bin->cb < 4*sizeof(uint32_t)) {
		return false;
	}
	rtfcp_init_decompress_state(prtf_bin->pb, prtf_bin->cb, &state);
	if (!rtfcp_verify_header(prtf_bin->pb, state.in_size, &header))
		return false;
	if (RTF_UNCOMPRESSED == header.magic) {
		if (*plength < prtf_bin->cb - 4*sizeof(uint32_t)) {
			return false;
		}
		memcpy(pbuff_out, prtf_bin->pb + 4*sizeof(uint32_t),
			prtf_bin->cb - 4*sizeof(uint32_t));
		return true;
	}
	rtfcp_init_output_state(&output,
		header.rawsize, pbuff_out, *plength);
	while (state.in_pos + 1 < state.in_size) {
		control = rtfcp_get_next_control(&state);
		for (bitmask_pos=0; bitmask_pos<8; bitmask_pos++) {
			if (control & (1 << bitmask_pos)) {
				dictref = rtfcp_get_next_dictionary_reference(&state);
				if (dictref.offset == state.dict_writeoffset) {
					*plength = output.out_pos;
					return true;
				}
				for (i =0; i<dictref.length; i++) {
					if (!rtfcp_check_output_overflow(&output))
						return false;
					c = rtfcp_get_dictionary_entry(
						&state, (dictref.offset + i));
					rtfcp_append_to_output(&output, c);
					rtfcp_append_to_dictionary(&state, c);
				}
			} else { /* its a literal */
				if (!rtfcp_check_output_overflow(&output))
					return false;
				c = rtf_get_next_literal(&state);
				if (!rtfcp_check_input_overflow(&state))
					return false;
				rtfcp_append_to_output(&output, c);
				rtfcp_append_to_dictionary(&state, c);
			}
		}
	}
	return true;
}

BINARY* rtfcp_compress(const char *pin_buff, const size_t in_length)
{
	EXT_PUSH ext_push;
	
	if (!ext_buffer_push_init(&ext_push, nullptr, 0, 0))
		return nullptr;
	if (ext_push.p_uint32(in_length + 12) != EXT_ERR_SUCCESS ||
	    ext_push.p_uint32(in_length) != EXT_ERR_SUCCESS ||
	    ext_push.p_uint32(RTF_UNCOMPRESSED) != EXT_ERR_SUCCESS ||
	    ext_push.p_uint32(0) != EXT_ERR_SUCCESS ||
	    ext_buffer_push_bytes(&ext_push, pin_buff, in_length) != EXT_ERR_SUCCESS) {
		return nullptr;
	}
	auto pbin = static_cast<BINARY *>(malloc(sizeof(BINARY)));
	if (pbin == nullptr) {
		return nullptr;
	}
	pbin->cb = ext_push.offset;
	pbin->pb = ext_buffer_push_release(&ext_push);
	return pbin;
}

ssize_t rtfcp_uncompressed_size(const BINARY *rtf)
{
	if (rtf->cb < 4 * sizeof(uint32_t))
		return -1;
	DECOMPRESSION_STATE state;
	COMPRESS_HEADER header;
	rtfcp_init_decompress_state(rtf->pb, rtf->cb, &state);
	if (!rtfcp_verify_header(rtf->pb, state.in_size, &header))
		return -1;
	if (header.rawsize > SIZE_MAX)
		return -1; /* just a limitation of this function */
	return header.rawsize;
}
