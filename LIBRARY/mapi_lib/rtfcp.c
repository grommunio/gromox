#include "ext_buffer.h"
#include "endian_macro.h"
#include <string.h>
#include <stdlib.h>
#include "rtfcp.h"

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


/* header for compressed rtf */
typedef struct _COMPRESS_HEADER {
	uint32_t size;
	uint32_t rawsize;
	uint32_t magic;
	uint32_t crc;
} COMPRESS_HEADER;

typedef struct _DECOMPRESSION_STATE {
	uint8_t dict[RTF_DICTLENGTH];
	uint32_t dict_writeoffset;
	uint8_t *compressed_data;
	uint32_t in_size;
	uint32_t in_pos;
} DECOMPRESSION_STATE;

typedef struct _OUTPUT_STATE {
	uint32_t out_size;
	uint32_t out_pos;
	char *pbuff_out;
	size_t max_length;
} OUTPUT_STATE;

typedef struct _DICTIONARYREF {
	uint8_t length;
	uint16_t offset;
} DICTIONARYREF;

static uint32_t g_crc_table[] = {
0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

static uint32_t rtfcp_crc(uint8_t *ptr, uint32_t count)
{
	uint32_t i;
	uint32_t crc;
	uint8_t table_position;
	uint32_t intermediatevalue;
	
	crc = 0;
	for (i=0; i<count; i++) {
		table_position = (crc ^ ptr[i]) & 0xFF;
		intermediatevalue = crc >> 8;
		crc = g_crc_table[table_position] ^ intermediatevalue;
	}
	return crc;
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

static BOOL rtfcp_verify_header(uint8_t *header_data,
	uint32_t in_size, COMPRESS_HEADER *pheader)
{
	pheader->size = IVAL(header_data, 0);   
	pheader->rawsize = IVAL(header_data, sizeof(uint32_t));
	pheader->magic = IVAL(header_data, 2*sizeof(uint32_t));  
	pheader->crc = IVAL(header_data, 3*sizeof(uint32_t));
	if (pheader->size != in_size - 4) {
		return FALSE;
	}
	if (pheader->magic != RTF_COMPRESSED &&
		pheader->magic != RTF_UNCOMPRESSED) {
		return FALSE;
	}
	return TRUE;
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

static BOOL rtfcp_check_output_overflow(OUTPUT_STATE *poutput)
{
	if (poutput->out_pos > poutput->out_size) {
		return FALSE;
	}
	return TRUE;
}

static BOOL rtfcp_check_input_overflow(DECOMPRESSION_STATE *state)
{
	if (state->in_pos > state->in_size) {
		return FALSE;
	}
	return TRUE;
}

BOOL rtfcp_uncompress(const BINARY *prtf_bin, char *pbuff_out, size_t *plength)
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
		return FALSE;
	}
	rtfcp_init_decompress_state(prtf_bin->pb, prtf_bin->cb, &state);
	if (FALSE == rtfcp_verify_header(
		prtf_bin->pb, state.in_size, &header)) {
		return FALSE;
	}
	if (RTF_UNCOMPRESSED == header.magic) {
		if (*plength < prtf_bin->cb - 4*sizeof(uint32_t)) {
			return FALSE;
		}
		memcpy(pbuff_out, prtf_bin->pb + 4*sizeof(uint32_t),
			prtf_bin->cb - 4*sizeof(uint32_t));
		return TRUE;
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
					return TRUE;
				}
				for (i =0; i<dictref.length; i++) {
					if (FALSE == rtfcp_check_output_overflow(&output)) {
						return FALSE;
					}
					c = rtfcp_get_dictionary_entry(
						&state, (dictref.offset + i));
					rtfcp_append_to_output(&output, c);
					rtfcp_append_to_dictionary(&state, c);
				}
			} else { /* its a literal */
				if (FALSE == rtfcp_check_output_overflow(&output)) {
					return FALSE;
				}
				c = rtf_get_next_literal(&state);
				if (FALSE == rtfcp_check_input_overflow(&state)) {
					return FALSE;
				}
				rtfcp_append_to_output(&output, c);
				rtfcp_append_to_dictionary(&state, c);
			}
		}
	}
	return TRUE;
}

static size_t rtfcp_longest_match(const char *prtf_buff,
	const size_t rtf_size, size_t input_idx, uint8_t *pdict,
	size_t *pwrite_idx, size_t *pmatch_offset, size_t *pmatch_length)
{
	size_t i;
	size_t until_idx;
	size_t match_length1;
	size_t best_match_length = 0;
	
	if (*pwrite_idx < RTF_DICTLENGTH) {
		until_idx = *pwrite_idx;
	} else {
		until_idx = RTF_DICTLENGTH;
	}
	for (i=0; i<until_idx; i++) {
		match_length1 = 0;
		while (prtf_buff[input_idx + match_length1] == pdict[i + match_length1]
			&& (i + match_length1) < ((*pwrite_idx) % RTF_DICTLENGTH) &&
			((input_idx + match_length1) < rtf_size) && match_length1 < 17) {
			match_length1 += 1;
			if (match_length1 > best_match_length) {
				best_match_length = match_length1;
				pdict[(*pwrite_idx) % RTF_DICTLENGTH] =
					prtf_buff[input_idx + match_length1 - 1];
				*pwrite_idx += 1;
				*pmatch_offset = i;
			}
		}
	}
	*pmatch_length = best_match_length;
	return best_match_length;
}

BINARY* rtfcp_compress(const char *pin_buff, const size_t in_length)
{
	BINARY *pbin;
	uint32_t crc;
	size_t input_idx;
	uint16_t dict_ref;
	EXT_PUSH ext_push;
	uint8_t control_bit;
	size_t dict_write_idx;
	size_t dict_match_length;
	size_t dict_match_offset;
	uint32_t control_byte_idx;
	uint8_t	dict[RTF_DICTLENGTH];
	
	input_idx = 0;
	control_bit = 0x01;
	if (FALSE == ext_buffer_push_init(&ext_push, NULL, 0, 0)) {
		return NULL;
	}
	control_byte_idx = 4*sizeof(uint32_t);
	if (EXT_ERR_SUCCESS != ext_buffer_push_advance(
		&ext_push, 4*sizeof(uint32_t))) {
		ext_buffer_push_free(&ext_push);
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(&ext_push, 0)) {
		ext_buffer_push_free(&ext_push);
		return FALSE;
	}
	memcpy(dict, RTF_INITDICT, RTF_INITLENGTH);
	dict_write_idx = RTF_INITLENGTH;
	while (input_idx < in_length) {
		dict_match_length = 0;
		dict_match_offset = 0;
		if (rtfcp_longest_match(pin_buff, in_length,
			input_idx, dict, &dict_write_idx,
			&dict_match_offset, &dict_match_length) > 1) {
			dict_ref = dict_match_offset << 4;
			dict_ref += dict_match_length - 2;
			input_idx += dict_match_length;
			ext_push.data[control_byte_idx] |= control_bit;
			if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
				&ext_push, (dict_ref & 0xFF00) >> 8) ||
				EXT_ERR_SUCCESS != ext_buffer_push_uint8(
				&ext_push, dict_ref & 0xFF)) {
				ext_buffer_push_free(&ext_push);
				return FALSE;
			}
		} else {
			if (0 == dict_match_length) {
				dict[dict_write_idx % RTF_DICTLENGTH] = pin_buff[input_idx];
				dict_write_idx ++;
			}
			if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
				&ext_push, pin_buff[input_idx])) {
				ext_buffer_push_free(&ext_push);
				return FALSE;
			}
			input_idx ++;
		}
		if (0x80 == control_bit) {
			control_bit = 0x01;
			control_byte_idx = ext_push.offset;
			if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(&ext_push, 0)) {
				ext_buffer_push_free(&ext_push);
				return FALSE;
			}
		} else {
			control_bit <<= 1;
		}
	}
	
	dict_ref = (dict_write_idx%RTF_DICTLENGTH) << 4;
	ext_push.data[control_byte_idx] |= control_bit;
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&ext_push, (dict_ref & 0xFF00) >> 8) ||
		EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&ext_push, dict_ref & 0xFF)) {
		ext_buffer_push_free(&ext_push);
		return FALSE;
	}
	pbin = malloc(sizeof(BINARY));
	if (NULL == pbin) {
		ext_buffer_push_free(&ext_push);
		return FALSE;
	}
	crc = rtfcp_crc(ext_push.data + 4*sizeof(uint32_t),
			ext_push.offset - 4*sizeof(uint32_t));
	pbin->cb = ext_push.offset;
	pbin->pb = ext_push.data;
	ext_push.offset = 0;
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		&ext_push, pbin->cb - sizeof(uint32_t)) ||
		EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		&ext_push, in_length) ||
		EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		&ext_push, RTF_COMPRESSED) ||
		EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		&ext_push, crc)) {
		free(pbin);
		ext_buffer_push_free(&ext_push);
		return FALSE;
	}
	return pbin;
}
