// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstring>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/lzxpress.hpp>
#define WINDOWS_SIZE				0x20

#define CLASSIC_MATCH_LENGTH		9	/* 3 + 6 */

#define MIDDLE_MATCH_LENGTH			24 /* 3 + 7 + 14 */

#define MAX_MATCH_LENGTH			279  /* 254 + 15 + 7 + 3 */

#define MIN(a,b)					((a)<(b)?(a):(b))


uint32_t lzxpress_compress(const uint8_t *uncompressed,
	uint32_t uncompressed_size, uint8_t *compressed)
{
	BOOL b_found;
	uint32_t indic;
	uint32_t offset;
	uint32_t length;
	uint16_t *pdest;
	uint32_t byte_left;
	uint8_t *ptr_indic;
	uint32_t indic_bit;
	uint32_t coding_pos;
	uint32_t match_offset;
	uint32_t nibble_index;
	uint32_t metadata_size;
	uint32_t compressed_pos;
	
	
	if (0 == uncompressed_size) {
		return 0;
	}
	
	coding_pos = 0;
	indic = 0;
	*(uint32_t *)compressed = 0;
	compressed_pos = sizeof(uint32_t);
	ptr_indic = compressed;
	byte_left = uncompressed_size;
	indic_bit = 0;
	nibble_index = 0;
	
	do {
		b_found = FALSE;
		match_offset = 0;
		offset = coding_pos - MIN(WINDOWS_SIZE, coding_pos);
		if (0 == offset) {
			offset ++;
		}
		while (offset < coding_pos) {
			for (length = 0;
				uncompressed[coding_pos + length]
				== uncompressed[offset + length] &&
				offset + length < coding_pos &&
				length < MAX_MATCH_LENGTH &&
				length < uncompressed_size - coding_pos - 1;
				length ++);
			if (length < 3) {
				offset ++;
				continue;
			}
			b_found = TRUE;
			match_offset = coding_pos - offset;
			break;
		}
		
		if (b_found) {
			metadata_size = 0;
			pdest = (uint16_t *)&compressed[compressed_pos];
			if (length <= CLASSIC_MATCH_LENGTH) {
				/* classical meta-data */
				uint16_t metadata = ((match_offset - 1) << 3) | (length - 3);
				cpu_to_le16p(&pdest[metadata_size/sizeof(uint16_t)], metadata);
				metadata_size += sizeof(uint16_t);
			} else {
				uint16_t metadata = ((match_offset - 1) << 3) | 7;
				cpu_to_le16p(&pdest[metadata_size/sizeof(uint16_t)], metadata);
				metadata_size += sizeof(uint16_t);
				if (length <= MIDDLE_MATCH_LENGTH) {
					/* shared byte */
					if (0 == nibble_index) {
						compressed[compressed_pos + metadata_size] =
											(length - (3 + 7)) & 0xF;
						metadata_size += sizeof(uint8_t);
					} else {
						compressed[nibble_index] &= 0xF;
						compressed[nibble_index] |= (length - (3 + 7)) * 16;
					}
				} else {
					if (length <= MAX_MATCH_LENGTH) {
						/* shared byte */
						if (0 == nibble_index) {
							compressed[compressed_pos + metadata_size] = 15;
							metadata_size += sizeof(uint8_t);
						} else {
							compressed[nibble_index] &= 0xF;
							compressed[nibble_index] |= (15 * 16);
						}
						/* additional length */
						compressed[compressed_pos + metadata_size] =
												length - (3 + 7 + 15);
						metadata_size += sizeof(uint8_t);
					} else {
						if (0 == nibble_index) {
							compressed[compressed_pos + metadata_size] |= 15;
							metadata_size += sizeof(uint8_t);
						} else {
							compressed[nibble_index] |= 15 << 4;
						}
						compressed[compressed_pos + metadata_size] = 255;
						metadata_size += sizeof(uint8_t);
						compressed[compressed_pos + metadata_size] =
													(length - 3) & 0xFF;
						compressed[compressed_pos + metadata_size + 1] =
												((length - 3) >> 8) & 0xFF;
						metadata_size += sizeof(uint16_t);
					}
				}
			}
			indic |= 1U << (32 - (indic_bit % 32 + 1));
			if (length > CLASSIC_MATCH_LENGTH) {
				if (nibble_index == 0) {
					nibble_index = compressed_pos + sizeof(uint16_t);
				} else {
					nibble_index = 0;
				}
			}
			compressed_pos += metadata_size;
			coding_pos += length;
			byte_left -= length;
		} else {
			compressed[compressed_pos] = uncompressed[coding_pos];
			compressed_pos ++;
			coding_pos ++;
			byte_left --;
		}
		indic_bit ++;
		if ((indic_bit - 1) % 32 > (indic_bit % 32)) {
			cpu_to_le32p(ptr_indic, indic);
			indic = 0;
			ptr_indic = &compressed[compressed_pos];
			compressed_pos += sizeof(uint32_t);
		}
	} while (byte_left > 3);
	
	do {
		compressed[compressed_pos] = uncompressed[coding_pos];
		indic_bit ++;
		coding_pos ++;
		compressed_pos ++;
		if ((indic_bit - 1) % 32 > (indic_bit % 32)) {
			cpu_to_le32p(ptr_indic, indic);
			indic = 0;
			ptr_indic = &compressed[compressed_pos];
			compressed_pos += sizeof(uint32_t);
		}
	} while (coding_pos < uncompressed_size);
	
	indic |= 1U << (32 - (indic_bit % 32 + 1));
	indic = cpu_to_le32(indic);
	memcpy(ptr_indic, &indic, sizeof(indic));
	return compressed_pos;
}

uint32_t lzxpress_decompress(const uint8_t *input, uint32_t input_size,
	uint8_t *output, uint32_t max_output_size)
{
	uint32_t length;
	uint32_t offset;
	uint32_t indicator;
	uint32_t input_index;
	uint32_t output_index;
	uint32_t nibble_index;
	uint32_t indicator_bit;
	
	length = 0;
	offset = 0;
	indicator = 0;
	input_index = 0;
	nibble_index = 0;
	output_index = 0;
	indicator_bit = 0;
	do {
		if (0 == indicator_bit) {
			if (input_index + sizeof(uint32_t) > input_size)
				return 0;
			indicator = le32p_to_cpu(&input[input_index]);
			input_index += sizeof(uint32_t);
			indicator_bit = 32;
		}
		indicator_bit --;
		/*
		 * check whether the bit specified by indicator_bit is set or not
		 * set in indicator. For example, if indicator_bit has value 4
		 * check whether the 4th bit of the value in indicator is set
		 */
		if (0 == ((indicator >> indicator_bit) & 1)) {
			if (output_index > max_output_size)
				break;
			output[output_index] = input[input_index];
			input_index += sizeof(uint8_t);
			output_index += sizeof(uint8_t);
			continue;
		}
		if (input_index + sizeof(uint16_t) > input_size)
			return 0;
		length = le16p_to_cpu(&input[input_index]);
		input_index += sizeof(uint16_t);
		offset = length / 8;
		length = length % 8;
		if (7 == length) {
			if (0 == nibble_index) {
				nibble_index = input_index;
				if (input_index >= input_size)
					return 0;
				length = input[input_index] % 16;
				input_index += sizeof(uint8_t);
			} else {
				if (nibble_index >= input_size)
					return 0;
				length = input[nibble_index] / 16;
				nibble_index = 0;
			}
			if (15 == length) {
				if (input_index >= input_size)
					return 0;
				length = input[input_index];
				input_index += sizeof(uint8_t);
				if (255 == length) {
					if (input_index + sizeof(uint16_t) > input_size)
						return 0;
					length = le16p_to_cpu(&input[input_index]);
					input_index += sizeof(uint16_t);
					length -= (15 + 7);
				}
				length += 15;
			}
			length += 7;
		}
		length += 3;
		do {
			if ((output_index >= max_output_size) ||
				((offset + 1) > output_index)) {
				break;
			}
			output[output_index] = output[output_index - offset - 1];
			output_index += sizeof(uint8_t);
			length -= sizeof(uint8_t);
		} while (length != 0);
	} while (output_index < max_output_size && input_index < (input_size));
	return output_index;
}
