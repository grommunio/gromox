// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2025 grommunio GmbH
// This file is part of Gromox.
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <libHX/endian.h>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/mail_func.hpp>
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

struct DICTIONARYREF {
	uint8_t length;
	uint16_t offset;
};

struct DECOMPRESSION_STATE {
	uint8_t dict[RTF_DICTLENGTH] = RTF_INITDICT;
	uint32_t dict_writeoffset = RTF_INITLENGTH;
	const uint8_t *compressed_data = nullptr;
	uint32_t in_size = 0, in_pos = RTF_HEADERLENGTH;

	DECOMPRESSION_STATE(std::string_view in) :
		compressed_data(reinterpret_cast<const uint8_t *>(in.data())),
		in_size(std::min(in.size(), static_cast<size_t>(UINT32_MAX - 12)))
	{}
	constexpr inline bool overflow_check() const { return in_pos <= in_size; }
	uint8_t get_next_byte();
	DICTIONARYREF get_next_dict_ref();
	inline uint8_t get_next_ctrl() { return get_next_byte(); }
	inline uint8_t get_next_literal() { return get_next_byte(); }
	void append_to_dict(char);
	inline char get_dict_entry(uint32_t i) const { return dict[i % RTF_DICTLENGTH]; }
};

struct OUTPUT_STATE {
	uint32_t out_size;
	uint32_t out_pos;
	char *pbuff_out;
	size_t max_length;

	constexpr inline bool overflow_check() const { return out_pos <= out_size; }
	void append(char);
};

}

static void rtfcp_init_output_state(OUTPUT_STATE *pstate,
	uint32_t rawsize, char *pbuff_out, size_t max_length)
{
	pstate->out_pos = 0;
	pstate->out_size = rawsize + RTF_HEADERLENGTH + 4;
	pstate->pbuff_out = pbuff_out;
	pstate->max_length = max_length;
}

static bool rtfcp_verify_header(const uint8_t *header_data,
	uint32_t in_size, COMPRESS_HEADER *pheader)
{
	pheader->size = le32p_to_cpu(&header_data[0]);
	pheader->rawsize = le32p_to_cpu(&header_data[4]);
	pheader->magic = le32p_to_cpu(&header_data[8]);
	pheader->crc = le32p_to_cpu(&header_data[12]);
	if (pheader->size != in_size - 4)
		return false;
	return pheader->magic == RTF_COMPRESSED ||
	       pheader->magic == RTF_UNCOMPRESSED;
}

uint8_t DECOMPRESSION_STATE::get_next_byte()
{
	auto pstate = this;
	uint8_t next_byte;
	
	if (pstate->in_pos > pstate->in_size)
		return 0;
	next_byte = pstate->compressed_data[pstate->in_pos++];
	return next_byte;
}

DICTIONARYREF DECOMPRESSION_STATE::get_next_dict_ref()
{
	DICTIONARYREF reference;
	auto highbyte = get_next_byte();
	auto lowbyte = get_next_byte();
	reference.length = lowbyte & 0x0F;
	reference.length += 2;
	reference.offset = ((highbyte << 8) + lowbyte);
	reference.offset &= 0xFFF0;
	reference.offset >>= 4;
	return reference;
}

void DECOMPRESSION_STATE::append_to_dict(char c)
{
	auto pstate = this;
	pstate->dict[pstate->dict_writeoffset] = c;
	pstate->dict_writeoffset =
		(pstate->dict_writeoffset + 1)%RTF_DICTLENGTH;
}

void OUTPUT_STATE::append(char c)
{
	auto poutput = this;
	poutput->pbuff_out[poutput->out_pos++] = c;
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

	if (prtf_bin->cb < 4*sizeof(uint32_t))
		return false;
	DECOMPRESSION_STATE state(*prtf_bin);
	if (!rtfcp_verify_header(prtf_bin->pb, state.in_size, &header))
		return false;
	if (RTF_UNCOMPRESSED == header.magic) {
		if (*plength < prtf_bin->cb - 4 * sizeof(uint32_t))
			return false;
		memcpy(pbuff_out, prtf_bin->pb + 4*sizeof(uint32_t),
			prtf_bin->cb - 4*sizeof(uint32_t));
		return true;
	}
	rtfcp_init_output_state(&output,
		header.rawsize, pbuff_out, *plength);
	while (state.in_pos + 1 < state.in_size) {
		control = state.get_next_ctrl();
		for (bitmask_pos=0; bitmask_pos<8; bitmask_pos++) {
			if (control & (1 << bitmask_pos)) {
				dictref = state.get_next_dict_ref();
				if (dictref.offset == state.dict_writeoffset) {
					*plength = output.out_pos;
					return true;
				}
				for (i =0; i<dictref.length; i++) {
					if (!output.overflow_check())
						return false;
					c = state.get_dict_entry(dictref.offset + i);
					output.append(c);
					state.append_to_dict(c);
				}
			} else { /* its a literal */
				if (!output.overflow_check())
					return false;
				c = state.get_next_literal();
				if (!state.overflow_check())
					return false;
				output.append(c);
				state.append_to_dict(c);
			}
		}
	}
	return true;
}

/**
 * This uses the MELA uncompressed format.
 * It is valid for @in and @out to refer to the same object.
 */
ec_error_t rtfcp_encode(std::string_view in, std::string &out) try
{
	uint32_t len = std::min(in.size(), static_cast<size_t>(UINT32_MAX - 12));
	char b[16];
	cpu_to_le32p(&b[0], len + 12);
	cpu_to_le32p(&b[4], len);
	cpu_to_le32p(&b[8], RTF_UNCOMPRESSED);
	cpu_to_le32p(&b[12], 0);
	out = std::string(b, sizeof(b)) + std::string_view(in.data(), len);
	/* In-place editing via string.insert(0,...) is some 90% slower in GNU stdlibc++ */
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecMAPIOOM;
}

ssize_t rtfcp_uncompressed_size(const BINARY *rtf)
{
	if (rtf->cb < 4 * sizeof(uint32_t))
		return -1;
	DECOMPRESSION_STATE state(*rtf);
	COMPRESS_HEADER header;
	if (!rtfcp_verify_header(rtf->pb, state.in_size, &header))
		return -1;
	if (static_cast<size_t>(header.rawsize) > SSIZE_MAX)
		return -1; /* just a limitation of this function */
	return header.rawsize;
}
