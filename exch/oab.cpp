// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
/*
 * MS-OXOAB Offline Address Book implementation.
 * Generates OAB Full Details files and XML manifest for Outlook clients.
 */
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include <fmt/core.h>
#include <openssl/evp.h>
#include <tinyxml2.h>
#include <gromox/ab_tree.hpp>
#include <gromox/clock.hpp>
#include <gromox/config_file.hpp>
#include <gromox/cryptoutil.hpp>
#include <gromox/defs.h>
#include <gromox/hpm_common.h>
#include <gromox/mapidefs.h>
#include <gromox/mapitags.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/plugin.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>

using namespace gromox;
using namespace gromox::ab_tree;

/* OAB v4 binary format constants */
static constexpr uint32_t OAB_V4_VERSION = 0x20;
static constexpr uint32_t OAB_TMPL_VERSION = 0x07;

/* Header schema (4 properties) */
static constexpr proptag_t hdr_props[] = {
	PR_OAB_NAME, PR_OAB_DN, PR_OAB_SEQUENCE, PR_OAB_CONTAINER_GUID,
};
static constexpr uint32_t hdr_flags[] = {0, 0, 0, 0};
static constexpr size_t HDR_PROP_COUNT = std::size(hdr_props);

/* Object schema (14 properties) */
static constexpr proptag_t obj_props[] = {
	PR_EMAIL_ADDRESS, PR_SMTP_ADDRESS, PR_DISPLAY_NAME, PR_OBJECT_TYPE,
	PR_DISPLAY_TYPE, PR_DISPLAY_TYPE_EX, PR_GIVEN_NAME, PR_SURNAME,
	PR_TITLE, PR_DEPARTMENT_NAME, PR_COMPANY_NAME, PR_OFFICE_LOCATION,
	PR_BUSINESS_TELEPHONE_NUMBER, PR_OAB_TRUNCATED_PROPS,
};
static constexpr uint32_t obj_flags[] = {
	2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};
static constexpr size_t OBJ_PROP_COUNT = std::size(obj_props);

namespace {

/* Cached OAB data for a single address book base */
struct oab_cache_entry {
	std::string manifest_xml, lzx_data, tmpl_lzx_data;
	gromox::time_point gen_time;
	uint32_t sequence = 1;
};

/* OAB binary writer helper */
class oab_writer {
	public:
	void put_u8(uint8_t v) { buf.push_back(v); }
	void put_u32le(uint32_t);
	void put_varui(uint32_t);
	void put_str(const std::string &);
	size_t begin_record();

	/**
	 * Patch the record size (cbSize) at the given offset. cbSize includes
	 * itself per MS-OXOAB v16 §2.9.5.
	 */
	void end_record(size_t off) { patch_u32le(off, buf.size() - off); }

	void patch_u32le(size_t off, uint32_t v);
	std::string &data() { return buf; }
	const std::string &data() const { return buf; }
	size_t size() const { return buf.size(); }

	private:
	std::string buf;
};

/**
 * LZX bitstream writer.
 *
 * LZX uses 16-bit LE words with bits consumed MSB-first.
 * Bits accumulate in a 32-bit register; when >=16 bits are
 * pending, the top 16 are flushed as a little-endian word.
 */
struct lzx_bitstream {
	std::string buf;
	uint32_t bits = 0;
	unsigned int n = 0; /* number of bits pending */

	void put_bits(unsigned count, uint32_t value);
	void flush();
};

/* Token produced by the match finder */
struct lzx_token {
	uint16_t main_sym;    /* 0-255 literal, 256+ match */
	uint8_t len_sym;      /* length tree symbol */
	bool has_len_sym;
	uint8_t footer_nbits; /* extra bits for position slot */
	uint32_t footer_val;
	uint32_t extra_len;   /* LZXD extended match: match_length - 257 */
};

} /* anon-ns */

/* LZX constants for 256 KB window (MS-OXOAB ulBlockMax=0x40000, window_bits=18) */
static constexpr unsigned LZX_NUM_POS_SLOTS = 36;
static constexpr unsigned LZX_MAIN_SYMBOLS = 256 + 8 * LZX_NUM_POS_SLOTS; /* 544 */
static constexpr unsigned LZX_LEN_SYMBOLS = 249;
static constexpr unsigned LZX_PRETREE_SYMBOLS = 20;
static constexpr unsigned LZX_MIN_MATCH = 2;
/*
 * LZX Delta extends maximum match from 257 to 33024 via an extra length
 * encoding after the standard length symbol. When the base match length
 * decodes as 257 (LZX_NUM_PRIMARY_LENGTHS + LZX_NUM_SECONDARY_LENGTHS - 1 +
 * LZX_MIN_MATCH), the decoder reads additional bits for the extension.
 */
static constexpr unsigned LZX_MAX_MATCH = 33024;

/* Extra footer bits per position slot */
static constexpr uint8_t lzx_extra_bits[LZX_NUM_POS_SLOTS] = {
	0,0,0,0, 1,1,2,2, 3,3,4,4, 5,5,6,6,
	7,7,8,8, 9,9,10,10, 11,11,12,12, 13,13,14,14, 15,15,16,16,
};

/* Base offset per position slot */
static constexpr uint32_t lzx_position_base[LZX_NUM_POS_SLOTS] = {
	0,1,2,3, 4,6,8,12, 16,24,32,48,
	64,96,128,192, 256,384,512,768,
	1024,1536,2048,3072, 4096,6144,8192,12288,
	16384,24576,32768,49152, 65536,98304,131072,196608,
};

void oab_writer::put_u32le(uint32_t v)
{
	buf.push_back(v & 0xFF);
	buf.push_back((v >> 8) & 0xFF);
	buf.push_back((v >> 16) & 0xFF);
	buf.push_back((v >> 24) & 0xFF);
}

/**
 * MS-OXOAB v16 §2.9.6.1 variable-length unsigned integer encoding.
 */
void oab_writer::put_varui(uint32_t v)
{
	if (v <= 0x7F) {
		buf.push_back(static_cast<uint8_t>(v));
	} else if (v <= 0xFF) {
		buf.push_back(0x81);
		buf.push_back(static_cast<uint8_t>(v));
	} else if (v <= 0xFFFF) {
		buf.push_back(0x82);
		buf.push_back(v & 0xFF);
		buf.push_back((v >> 8) & 0xFF);
	} else if (v <= 0xFFFFFF) {
		buf.push_back(0x83);
		buf.push_back(v & 0xFF);
		buf.push_back((v >> 8) & 0xFF);
		buf.push_back((v >> 16) & 0xFF);
	} else {
		buf.push_back(0x84);
		put_u32le(v);
	}
}

/**
 * Null-terminated string (PT_UNICODE or PT_STRING8). The caller must
 * ensure the string is non-empty; empty strings are not encoded but
 * marked absent in the presence bit array instead (v16 §2.9.6.3).
 */
void oab_writer::put_str(const std::string &s)
{
	buf.append(s.data(), s.data() + s.size() + 1); /* includes \0 this way */
}

/**
 * Write placeholder for record size, return offset for later patching.
 */
size_t oab_writer::begin_record()
{
	auto off = buf.size();
	put_u32le(0); // placeholder
	return off;
}

/**
 * Patch a uint32_t at a given offset
 */
void oab_writer::patch_u32le(size_t off, uint32_t v)
{
	buf[off]   = v & 0xFF;
	buf[off+1] = (v >> 8) & 0xFF;
	buf[off+2] = (v >> 16) & 0xFF;
	buf[off+3] = (v >> 24) & 0xFF;
}

void lzx_bitstream::put_bits(unsigned int count, uint32_t value)
{
	/*
	 * For counts > 16 (e.g. the 24-bit block_size
	 * field), split into two halves to keep each
	 * shift in range.
	 */
	if (count > 16) {
		unsigned int hi = count - 16;
		put_bits(hi, value >> 16);
		put_bits(16, value & 0xFFFF);
		return;
	}
	bits |= (value & ((1U << count) - 1)) << (32 - n - count);
	n += count;
	if (n < 16)
		return;
	uint16_t w = bits >> 16;
	buf.push_back(w & 0xFF);
	buf.push_back((w >> 8) & 0xFF);
	bits <<= 16;
	n -= 16;
}

void lzx_bitstream::flush()
{
	if (n <= 0)
		return;
	uint16_t w = bits >> 16;
	buf.push_back(w & 0xFF);
	buf.push_back((w >> 8) & 0xFF);
	bits = 0;
	n = 0;
}

/**
 * CRC-32 for OAB LZX_BLK headers (polynomial 0xEDB88320).
 *
 * libmspack's OAB decompressor compares the running CRC (seeded
 * 0xFFFFFFFF, no final XOR) directly against the stored value.
 * So we store the running CRC, not the standard finalized one.
 */
static uint32_t crc32_oab(const void *data, size_t len)
{
	auto p = static_cast<const uint8_t *>(data);
	uint32_t crc = 0xFFFFFFFF;
	for (size_t i = 0; i < len; ++i) {
		crc ^= p[i];
		for (int j = 0; j < 8; ++j)
			crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
	}
	return crc; /* running CRC, no final XOR */
}

/**
 * Build canonical Huffman code lengths from symbol frequencies.
 * Two-queue approach with length limiting via Kraft inequality.
 */
static void huff_build(const uint32_t *freq, unsigned int nsyms,
    uint8_t *lengths, unsigned max_len)
{
	memset(lengths, 0, nsyms);

	struct sym_freq {
		uint32_t f = 0;
		unsigned int sym = 0;
		auto operator<=>(const sym_freq &) const = default;
	};
	std::vector<sym_freq> active;
	active.reserve(nsyms);
	for (unsigned int i = 0; i < nsyms; ++i)
		if (freq[i] > 0)
			active.emplace_back(freq[i], i);

	if (active.empty())
		return;
	if (active.size() == 1) {
		/*
		 * A single symbol needs length 1 but would leave half the
		 * Huffman code space empty. Decoders such as the MonoGame
		 * LzxDecoder reject incomplete trees (MakeDecodeTable returns
		 * error), so assign a dummy second symbol to form a complete
		 * binary tree. The dummy code is never emitted.
		 */
		lengths[active[0].sym] = 1;
		unsigned int dummy = active[0].sym == 0 ? 1 : 0;
		lengths[dummy] = 1;
		return;
	}

	std::sort(active.begin(), active.end());
	size_t nact = active.size();
	std::vector<uint64_t> node_freq(2 * nact);
	std::vector<unsigned int> depth(2 * nact, 0), left_child(2 * nact), right_child(2 * nact);

	for (size_t i = 0; i < nact; ++i)
		node_freq[i] = active[i].f;

	size_t leaf = 0, intern = nact, next = nact;

	auto pick_min = [&]() -> size_t {
		size_t idx;
		if (leaf < nact && (intern >= next ||
		     node_freq[leaf] <= node_freq[intern]))
			idx = leaf++;
		else
			idx = intern++;
		return idx;
	};

	for (size_t i = 0; i < nact - 1; ++i) {
		size_t a = pick_min();
		size_t b = pick_min();
		node_freq[next] = node_freq[a] + node_freq[b];
		depth[next] = std::max(depth[a], depth[b]) + 1;
		left_child[next] = a;
		right_child[next] = b;
		++next;
	}

	/* Walk tree to assign depths to leaves */
	std::vector<unsigned int> stack, node_depth(next, 0);
	size_t root = next - 1;
	node_depth[root] = 0;
	stack.push_back(root);
	bool over = false;
	while (!stack.empty()) {
		auto nd = stack.back();
		stack.pop_back();
		if (nd < nact) {
			auto d = node_depth[nd];
			if (d > max_len)
				over = true;
			lengths[active[nd].sym] = std::min(d, max_len);
			continue;
		}
		auto lc = left_child[nd];
		auto rc = right_child[nd];
		node_depth[lc] = node_depth[nd] + 1;
		node_depth[rc] = node_depth[nd] + 1;
		stack.push_back(lc);
		stack.push_back(rc);
	}

	/*
	 * Length limiting via Kraft inequality: if any code was
	 * clamped to max_len, the Kraft sum is over-full. Fix by
	 * lengthening the shortest codes to free budget.
	 */
	if (!over)
		return;

	for (unsigned int i = 0; i < nsyms; ++i)
		if (lengths[i] > max_len)
			lengths[i] = max_len;

	for (;;) {
		int64_t kraft = 0;
		for (unsigned int i = 0; i < nsyms; ++i)
			if (lengths[i] > 0)
				kraft += 1LL << (max_len - lengths[i]);

		int64_t target = 1LL << max_len;
		if (kraft <= target)
			break;

		unsigned int shortest = max_len;
		for (unsigned int i = 0; i < nsyms; ++i)
			if (lengths[i] > 0 && lengths[i] < shortest)
				shortest = lengths[i];

		for (unsigned int i = 0; i < nsyms; ++i)
			if (lengths[i] == shortest && kraft > target) {
				kraft -= 1LL << (max_len - lengths[i]);
				++lengths[i];
				kraft += 1LL << (max_len - lengths[i]);
			}
	}
}

/**
 * Generate canonical Huffman codes from code lengths.
 * Standard bl_count / next_code algorithm per RFC 1951.
 */
static void huff_make_codes(const uint8_t *lengths, unsigned int nsyms,
    uint16_t *codes, unsigned int max_len)
{
	unsigned int bl_count[17]{};
	for (unsigned int i = 0; i < nsyms; ++i)
		if (lengths[i] > 0)
			++bl_count[lengths[i]];

	uint32_t next_code[17]{}, code = 0;
	for (unsigned int bits = 1; bits <= max_len; ++bits) {
		code = (code + bl_count[bits - 1]) << 1;
		next_code[bits] = code;
	}

	for (unsigned int i = 0; i < nsyms; ++i) {
		if (lengths[i] > 0) {
			codes[i] = next_code[lengths[i]];
			++next_code[lengths[i]];
		} else {
			codes[i] = 0;
		}
	}
}

/**
 * Encode one tree-delta segment via a pretree.
 * LZX encodes path-length differences as (prev - cur + 17) % 17,
 * with RLE codes 17 (4-19 zeros), 18 (20-51 zeros),
 * 19 (4-5 same non-zero delta).
 *
 * Important: codes 17/18 unconditionally SET lengths to zero in the decoder.
 * They must only be used for runs where the TARGET length (cur_lengths[i]) is
 * zero. A zero delta with a non-zero target must be encoded as literal symbol
 * 0.
 */
static void lzx_encode_pretree(lzx_bitstream &bs, const uint8_t *prev_lengths,
    const uint8_t *cur_lengths, unsigned int count)
{
	std::vector<uint8_t> deltas(count);
	for (unsigned int i = 0; i < count; ++i)
		deltas[i] = (prev_lengths[i] - cur_lengths[i] + 17) % 17;

	struct pretree_code {
		uint8_t code = 0, extra = 0, extra_bits = 0;
	};
	std::vector<pretree_code> codes;
	codes.reserve(count);

	for (unsigned int i = 0; i < count; ) {
		/*
		 * Codes 17/18: run of 4+ positions where cur_lengths[i] == 0.
		 * The decoder sets those positions to zero unconditionally.
		 */
		if (cur_lengths[i] == 0) {
			unsigned int run = 1;
			while (i + run < count && cur_lengths[i+run] == 0)
				++run;
			while (run >= 20) {
				unsigned int emit = std::min(run, 51U);
				codes.emplace_back(18, emit - 20, 5);
				run -= emit;
				i += emit;
			}
			if (run >= 4) {
				codes.emplace_back(17, run - 4, 4);
				i += run;
			} else {
				for (unsigned int j = 0; j < run; ++j)
					codes.emplace_back(deltas[i+j], 0, 0);
				i += run;
			}
			continue;
		} else if (deltas[i] == 0) {
			/* Emit literal symbol 0 (no change). */
			codes.emplace_back(0, 0, 0);
			++i;
			continue;
		}

		/*
		 * Non-zero delta: try code 19 (RLE for 4-5 same
		 * non-zero delta values). The decoder computes the new
		 * length from the FIRST position's prev only, so all
		 * positions must share the same target length.
		 */
		unsigned int run = 1;
		while (i + run < count && deltas[i+run] == deltas[i] &&
		       cur_lengths[i+run] == cur_lengths[i])
			++run;
		if (run < 4) {
			codes.emplace_back(deltas[i++], 0, 0);
			continue;
		}
		while (run >= 4) {
			auto emit = std::min(run, 5U);
			codes.emplace_back(19, emit - 4, 1);
			codes.emplace_back(deltas[i], 0, 0);
			run -= emit;
			i += emit;
		}
		for (unsigned int j = 0; j < run; ++j)
			codes.emplace_back(deltas[i++], 0, 0);
	}

	/* Build pretree Huffman from the code stream */
	uint32_t pt_freq[LZX_PRETREE_SYMBOLS]{};
	for (auto &c : codes)
		++pt_freq[c.code];

	uint8_t pt_lengths[LZX_PRETREE_SYMBOLS]{};
	uint16_t pt_codes[LZX_PRETREE_SYMBOLS]{};
	huff_build(pt_freq, LZX_PRETREE_SYMBOLS, pt_lengths, 15);
	huff_make_codes(pt_lengths, LZX_PRETREE_SYMBOLS, pt_codes, 15);

	/* 20 pretree path lengths (4 bits each) */
	for (unsigned int i = 0; i < LZX_PRETREE_SYMBOLS; ++i)
		bs.put_bits(4, pt_lengths[i]);

	for (auto &c : codes) {
		bs.put_bits(pt_lengths[c.code], pt_codes[c.code]);
		if (c.code == 17)
			bs.put_bits(4, c.extra);
		else if (c.code == 18)
			bs.put_bits(5, c.extra);
		else if (c.code == 19)
			bs.put_bits(1, c.extra);
	}
}

/**
 * Find the position slot for a formatted offset
 */
static unsigned int lzx_position_slot(uint32_t foff)
{
	for (unsigned int s = 1; s < LZX_NUM_POS_SLOTS; ++s)
		if (foff < lzx_position_base[s])
			return s - 1;
	return LZX_NUM_POS_SLOTS - 1;
}

/**
 * Compute the number of main tree elements for a given uncompressed block
 * size. libmspack's OAB decompressor (oabd.c) creates a fresh LZX decoder per
 * block with window_bits derived from blk_dsize:
 *
 *   window_bits = 17;
 *   while (window_bits < 25 && (1 << window_bits) < blk_dsize)
 *       window_bits++;
 *   posn_slots = window_bits << 1;   (for window_bits <= 19)
 *   num_main_elements = 256 + posn_slots * 8;
 */
static unsigned int lzx_main_elements_for(size_t blk_dsize)
{
	unsigned int wb = 17, posn_slots;
	while (wb < 25 && (1u << wb) < blk_dsize)
		++wb;
	if (wb == 20)
		posn_slots = 42;
	else if (wb == 21)
		posn_slots = 50;
	else
		posn_slots = wb << 1;
	return 256 + posn_slots * 8;
}

static constexpr unsigned int LZX_HASH_BITS = 13;
static constexpr unsigned int LZX_HASH_SIZE = 1u << LZX_HASH_BITS;

static inline uint32_t lzx_hash3(const uint8_t *p)
{
	uint32_t v = p[0] | (static_cast<uint32_t>(p[1]) << 8) |
	             (static_cast<uint32_t>(p[2]) << 16);
	return (v * 0x1E35A7BD) >> (32 - LZX_HASH_BITS);
}

/**
 * Greedy hash-based match finder with R0/R1/R2 repeated
 * offset LRU. Produces an LZX token stream from raw data.
 */
static std::vector<lzx_token> lzx_find_matches(const uint8_t *data, size_t len,
    uint32_t &R0, uint32_t &R1, uint32_t &R2)
{
	std::vector<lzx_token> tokens;
	tokens.reserve(len);

	uint32_t htab[LZX_HASH_SIZE];
	std::fill(std::begin(htab), std::end(htab), UINT32_MAX);

	for (size_t pos = 0; pos < len; ) {
		size_t remain = len - pos;
		uint32_t best_len = 0, best_offset = 0;
		bool best_is_repeat = false;
		unsigned int best_repeat_slot = 0;

		/* Check repeated offsets (slots 0, 1, 2) */
		uint32_t repeats[3] = {R0, R1, R2};
		for (unsigned int ri = 0; ri < 3; ++ri) {
			uint32_t off = repeats[ri];
			if (off > pos)
				continue;
			auto mp = data + pos - off;
			uint32_t mlen = 0;
			auto max_m = std::min(static_cast<size_t>(LZX_MAX_MATCH), remain);
			while (mlen < max_m && data[pos+mlen] == mp[mlen])
				++mlen;
			if (mlen >= LZX_MIN_MATCH && mlen > best_len) {
				best_len = mlen;
				best_offset = off;
				best_is_repeat = true;
				best_repeat_slot = ri;
			}
		}

		/* Hash lookup needs 3 bytes */
		if (remain >= 3) {
			uint32_t h = lzx_hash3(data + pos);
			uint32_t prev = htab[h];
			if (prev != 0xFFFFFFFF && pos > prev) {
				uint32_t dist = pos - prev;
				/* max encodable distance for the 256 KB window */
				if (dist <= 262141) {
					auto mp = data + prev;
					uint32_t mlen = 0;
					auto max_m = std::min(static_cast<size_t>(LZX_MAX_MATCH), remain);
					while (mlen < max_m && data[pos+mlen] == mp[mlen])
						++mlen;
					if (mlen >= LZX_MIN_MATCH && mlen > best_len) {
						best_len = mlen;
						best_offset = dist;
						best_is_repeat = false;
					}
				}
			}
			htab[h] = pos;
		}

		if (best_len < LZX_MIN_MATCH) {
			tokens.emplace_back(data[pos], 0, false, 0, 0, 0);
			++pos;
			continue;
		}

		/* Update R0/R1/R2 */
		if (best_is_repeat) {
			switch (best_repeat_slot) {
			case 0: break;
			case 1: std::swap(R0, R1); break;
			case 2: std::swap(R0, R2); break;
			}
		} else {
			R2 = R1; R1 = R0; R0 = best_offset;
		}

		/*
		 * Encode match as LZX token. LZXD extended matches: when
		 * base_len == 257 the decoder reads extra_len bits, so cap the
		 * Huffman-encoded length at 257 and store the remainder.
		 */
		uint32_t base_len = std::min(best_len, 257u);
		uint32_t length_header = std::min(base_len - LZX_MIN_MATCH, 7u);
		uint32_t formatted_offset = best_is_repeat ? best_repeat_slot : (best_offset + 2);
		unsigned int slot = best_is_repeat ? best_repeat_slot :
		                    lzx_position_slot(formatted_offset);
		uint16_t main_sym = 256 + slot * 8 + length_header;

		lzx_token tok;
		tok.main_sym = main_sym;
		tok.has_len_sym = (length_header == 7);
		tok.len_sym = tok.has_len_sym ? static_cast<uint8_t>(base_len - LZX_MIN_MATCH - 7) : 0;
		tok.extra_len = best_len > 257 ? best_len - 257 : 0;

		if (!best_is_repeat && lzx_extra_bits[slot] > 0) {
			tok.footer_nbits = lzx_extra_bits[slot];
			tok.footer_val = formatted_offset - lzx_position_base[slot];
		} else {
			tok.footer_nbits = 0;
			tok.footer_val = 0;
		}

		tokens.emplace_back(tok);

		/* Hash intermediate positions */
		for (uint32_t j = 1; j < best_len && pos + j + 2 < len; ++j)
			htab[lzx_hash3(data + pos + j)] = pos + j;

		pos += best_len;
	}
	return tokens;
}

/**
 * Encode LZXD extended match length.
 *
 * When the base match length decodes as 257 (LZX_MAX_MATCH in the standard LZX
 * sense), the LZXD decoder reads additional bits to extend the match length.
 * The encoding uses a 4-entry prefix tree:
 *
 *   '0'   + 8 bits  → extra_len 0..255
 *   '10'  + 10 bits → extra_len 0x100..0x4FF
 *   '110' + 12 bits → extra_len 0x500..0x14FF
 *   '111' + 15 bits → extra_len 0..0x7FFF
 */
static void lzx_encode_extra_len(lzx_bitstream &bs, uint32_t extra_len)
{
	if (extra_len <= 0xFF) {
		bs.put_bits(1, 0);
		bs.put_bits(8, extra_len);
	} else if (extra_len <= 0x4FF) {
		bs.put_bits(2, 2); /* '10' */
		bs.put_bits(10, extra_len - 0x100);
	} else if (extra_len <= 0x14FF) {
		bs.put_bits(3, 6); /* '110' */
		bs.put_bits(12, extra_len - 0x500);
	} else {
		bs.put_bits(3, 7); /* '111' */
		bs.put_bits(15, extra_len);
	}
}

/**
 * Emit compressed tokens using main and length Huffman codes
 */
static void lzx_encode_tokens(lzx_bitstream &bs,
    const std::vector<lzx_token> &tokens, const uint8_t *main_lengths,
    const uint16_t *main_codes, const uint8_t *len_lengths,
    const uint16_t *len_codes)
{
	for (auto &t : tokens) {
		bs.put_bits(main_lengths[t.main_sym], main_codes[t.main_sym]);
		if (t.main_sym < 256)
			continue;
		if (t.has_len_sym)
			bs.put_bits(len_lengths[t.len_sym], len_codes[t.len_sym]);
		if (t.footer_nbits > 0)
			bs.put_bits(t.footer_nbits, t.footer_val);
		/*
		 * LZXD extended match: when the base match length is 257, emit
		 * extra_len.
		 */
		if (t.has_len_sym && t.len_sym == 248)
			lzx_encode_extra_len(bs, t.extra_len);
	}
}

/**
 * Encode a data block as an independent LZXD verbatim chunk.
 *
 * Per MS-PATCH v12 §2.2.1, LZXD compressed data consists of 32 KB chunks, each
 * preceded by a 16-bit LE chunk_size prefix. This function produces one
 * complete LZXD chunk (prefix + E8 header + verbatim block + padding).
 *
 * Each OAB LZX_BLK creates a new decoder (libmspack oabd.c), so each chunk is
 * self-contained with fresh R0/R1/R2, E8 header, and tree lengths starting
 * from zero.
 *
 * num_main is the number of main tree elements the decoder expects (derived
 * from the decoder's window size).
 */
static std::string lzxd_encode_verbatim(const void *vdata, size_t len,
    unsigned int num_main)
{
	auto data = static_cast<const uint8_t *>(vdata);
	uint32_t R0 = 1, R1 = 1, R2 = 1;
	auto tokens = lzx_find_matches(data, len, R0, R1, R2);

	/* Collect symbol frequencies */
	uint32_t main_freq[LZX_MAIN_SYMBOLS]{};
	uint32_t len_freq[LZX_LEN_SYMBOLS]{};
	for (auto &t : tokens) {
		++main_freq[t.main_sym];
		if (t.has_len_sym)
			++len_freq[t.len_sym];
	}

	/* Build Huffman codes (only for num_main elements) */
	uint8_t main_lengths[LZX_MAIN_SYMBOLS]{};
	uint16_t main_codes[LZX_MAIN_SYMBOLS]{};
	huff_build(main_freq, num_main, main_lengths, 16);
	huff_make_codes(main_lengths, num_main, main_codes, 16);

	uint8_t len_lengths[LZX_LEN_SYMBOLS]{};
	uint16_t len_codes[LZX_LEN_SYMBOLS]{};
	huff_build(len_freq, LZX_LEN_SYMBOLS, len_lengths, 16);
	huff_make_codes(len_lengths, LZX_LEN_SYMBOLS, len_codes, 16);

	lzx_bitstream bs;
	bs.buf.reserve(len + 2);

	/*
	 * MS-PATCH v12 §2.2.1: 16-bit LE chunk_size prefix.
	 * Reserve 2 bytes; backpatch after encoding.
	 */
	bs.buf.push_back(0);
	bs.buf.push_back(0);

	/* E8 call translation header (each chunk is independent) */
	bs.put_bits(1, 0); /* E8=0 (no translation) */

	/* Block type=1 (verbatim), block size (24 bits) */
	bs.put_bits(3, 1);
	bs.put_bits(24, len);

	/*
	 * Encode trees via pretree. Each block starts from zero previous
	 * lengths (fresh decoder).
	 */
	uint8_t zeros[LZX_MAIN_SYMBOLS]{};
	lzx_encode_pretree(bs, zeros, main_lengths, 256);
	lzx_encode_pretree(bs, zeros + 256, main_lengths + 256, num_main - 256);

	uint8_t len_zeros[LZX_LEN_SYMBOLS]{};
	lzx_encode_pretree(bs, len_zeros, len_lengths, LZX_LEN_SYMBOLS);

	/* Emit compressed tokens */
	lzx_encode_tokens(bs, tokens, main_lengths, main_codes,
	                  len_lengths, len_codes);
	bs.flush();

	/*
	 * Backpatch chunk_size: number of compressed bytes following the
	 * 2-byte prefix (MS-PATCH v12 §2.2.1).
	 */
	uint16_t chunk_size = bs.buf.size() - 2;
	bs.buf[0] = chunk_size & 0xFF;
	bs.buf[1] = (chunk_size >> 8) & 0xFF;

	return std::move(bs.buf);
}

/**
 * Encode a raw data block as an LZXD type 3 block (uncompressed), as per
 * MS-PATCH §2.2.3. The LZXD bitstream uses 16-bit LE words with bits consumed
 * MSB-first.
 *
 * Layout:
 * - 16-bit LE chunk size (byte count after this field, incl. padding)
 * - 1-bit E8 translation flag (0 = disabled)
 * - 3-bit block type (3 = uncompressed)
 * - 24-bit block size (decompressed byte count)
 * - 0-15 bits of padding up to next 16-bit word boundary
 * - 3x uint32_t LE variables R0, R1, R2 (recent match offsets, set to 1)
 * - N bytes of raw data
 * - 0-1 bytes padding to restore 16-bit alignment
 */
static std::string lzxd_encode_uncompressed(const void *vdata, size_t len)
{
	/*
	 * After the chunk size word we emit:
	 * - 2 bytes: (E8+type+block_size_hi in one 16-bit word)
	 * - 2 bytes: (block_size_lo+padding in one 16-bit word)
	 * - 12 bytes:  R0, R1, R2
	 * - len bytes of raw data
	 * - 0 or 1 byte padding for 16-bit alignment
	 */
	auto data = static_cast<const uint8_t *>(vdata);
	size_t padded = len + (len & 1);
	size_t chunk_payload = 4 + 12 + padded;
	std::string out;
	out.reserve(2 + chunk_payload);

	/* Chunk size (16-bit LE): bytes following this field */
	uint16_t cs = static_cast<uint16_t>(chunk_payload);
	out.push_back(cs & 0xFF);
	out.push_back((cs >> 8) & 0xFF);

	/*
	 * Pack bit fields into 16-bit LE words (MSB-first).
	 *
	 * Word 0: E8(1) | type(3) | block_size[23:12]
	 * Word 1: block_size[11:0] | padding(4)
	 */
	uint32_t bs = static_cast<uint32_t>(len);
	uint16_t w0 = (0 << 15)
	            | (3 << 12)
	            | ((bs >> 12) & 0xFFF);
	uint16_t w1 = ((bs & 0xFFF) << 4);

	out.push_back(w0 & 0xFF);
	out.push_back((w0 >> 8) & 0xFF);
	out.push_back(w1 & 0xFF);
	out.push_back((w1 >> 8) & 0xFF);

	/* R0=1, R1=1, R2=1 (recent match offsets, LE) */
	auto put_u32 = [&out](uint32_t v) {
		out.push_back(v & 0xFF);
		out.push_back((v >> 8) & 0xFF);
		out.push_back((v >> 16) & 0xFF);
		out.push_back((v >> 24) & 0xFF);
	};
	put_u32(1);
	put_u32(1);
	put_u32(1);

	/* Raw data bytes */
	out.append(reinterpret_cast<const char *>(data), len);

	/* Pad to 16-bit alignment */
	if (len & 1)
		out.push_back(0);

	return out;
}

/**
 * Wrap uncompressed OAB binary data (MS-OXOAB v16 §2.11) in various ways.
 *
 * @mode: 0: wrap OAB with LZX_HDR + LZX_BLK
 *        1: wrap OAB with LZX_HDR + LZX_BLK + LZXD type 1 frames
 *        3: wrap OAB with LZX_HDR + LZX_BLK + LZXD type 3 frames
 *
 * OL2021 violates the MS-OXOAB specification, ignores the LZX_BLK::ulFlags
 * and always treats data as LZXD. Thus we are never using mode 0 in practice.
 * (But Evolution-EWS is ok with getting mode 0-wrapped data.)
 */
static std::string oab_wrap_lzx(const std::string &raw, unsigned int mode)
{
	static constexpr size_t BLOCK_MAX_HDR = 0x40000; /* ulBlockMax in LZX_HDR */
	static constexpr size_t CHUNK_SIZE = 32768;      /* LZXD chunk = 32 KB */
	std::string out;

	auto put_u32 = [&out](uint32_t v) {
		out.push_back(v & 0xFF);
		out.push_back((v >> 8) & 0xFF);
		out.push_back((v >> 16) & 0xFF);
		out.push_back((v >> 24) & 0xFF);
	};

	/* LZX_HDR */
	put_u32(3); /* ulVersionHi */
	put_u32(1); /* ulVersionLo */
	put_u32(BLOCK_MAX_HDR); /* ulBlockMax */
	put_u32(raw.size()); /* ulTargetSize */

	if (raw.empty()) {
		/* Empty block: use ulFlags=0 stored (zero bytes to copy) */
		put_u32(0);
		put_u32(0);
		put_u32(0);
		put_u32(crc32_oab(nullptr, 0));
		return out;
	}

	size_t pos = 0;
	while (pos < raw.size()) {
		uint32_t chunk = std::min(raw.size() - pos, mode == 0 ? BLOCK_MAX_HDR : CHUNK_SIZE);
		auto blk_crc = crc32_oab(raw.data() + pos, chunk);

		if (mode == 0) {
			/*
			 * LZX_BLK with uncompressed payload, as per MS-OXOAB v16 §2.11.2.
			 * Works with Evolution-EWS's gal-lzx-decompress-test.
			 */
			put_u32(0); // ulFlags: not compressed (stored)
			put_u32(chunk); // ulCompSize: same as uncompressed for stored
			put_u32(chunk); // ulUncompSize
			put_u32(blk_crc); // ulCRC: CRC32 of decompressed block
			out.append(raw, pos, chunk);
		} else if (mode == 1) {
			/*
			 * LZX_BLK with LZXD payload (MS-OXOAB v16 §2.11.2).
			 * LZXD frame with compressed payload.
			 */
			auto num_main = lzx_main_elements_for(chunk);
			auto blk = lzxd_encode_verbatim(&raw[pos], chunk, num_main);
			put_u32(1); /* ulFlags: LZX compressed */
			put_u32(blk.size()); /* ulCompSize */
			put_u32(chunk); /* ulUncompSize */
			put_u32(blk_crc); /* ulCRC of decompressed data */
			out += std::move(blk);
		} else if (mode == 3) {
			/*
			 * LZX_BLK with LZXD payload (MS-OXOAB v16 §2.11.2).
			 * LZXD frame with uncompressed payload (MS-PATCH v12 §2.3.1.1).
			 */
			auto blk = lzxd_encode_uncompressed(&raw[pos], chunk);
			put_u32(1); /* ulFlags: LZX compressed */
			put_u32(blk.size()); /* ulCompSize */
			put_u32(chunk); /* ulUncompSize */
			put_u32(blk_crc); /* ulCRC of decompressed data */
			out += std::move(blk);
		}
		pos += chunk;
	}
	return out;
}

/**
 * Compute SHA-1 hex digest of data (MS-OXWOAB specifies SHA-1, 40 hex chars)
 */
static std::string sha1_hex(std::string_view input)
{
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int len = 0;
	std::unique_ptr<EVP_MD_CTX, sslfree> ctx(EVP_MD_CTX_new());
	if (ctx == nullptr)
		return {};
	if (EVP_DigestInit_ex(ctx.get(), EVP_sha1(), nullptr) <= 0 ||
	    EVP_DigestUpdate(ctx.get(), input.data(), input.size()) <= 0 ||
	    EVP_DigestFinal_ex(ctx.get(), hash, &len) <= 0)
		return {};
	return bin2hex(hash, len);
}

/**
 * Generate a deterministic GUID string from base_id
 * so the URL remains stable across ab_tree cache reloads.
 */
static std::string deterministic_guid(int32_t base_id)
{
	uint32_t v = base_id;
	return fmt::format("{:08x}-baad-cafe-0ab0-{:012x}", v, v);
}

/**
 * Map display_type (etyp) to MAPI PidTagObjectType value
 */
static uint32_t etyp_to_objtype(enum display_type dt)
{
	switch (dt) {
	case DT_DISTLIST:
	case DT_PRIVATE_DISTLIST:
		return static_cast<uint32_t>(MAPI_DISTLIST);
	case DT_FORUM:
		return static_cast<uint32_t>(MAPI_FOLDER);
	default:
		return static_cast<uint32_t>(MAPI_MAILUSER);
	}
}

/**
 * Generate a minimal OAB display template file (MS-OXOAB v12 §2.2). The
 * template file is a package of TMPLT_ENTRY structures describing how to
 * display Address Book objects. Clients that do not use templates still
 * require the <Template> element in the manifest to consider it valid per
 * MS-OXWOAB.
 *
 * Structure:
 *   OAB_HDR:          12 bytes (ulVersion=7, ulSerial=0, ulTotRecs=0)
 *   7x TMPLT_ENTRY:  224 bytes (all zeros — no template data)
 *   NAMES_STRUCT:     16 bytes (all zeros — no named properties)
 *   address templates: 4 bytes (oot-count = 0)
 */
static std::string generate_template_raw()
{
	static constexpr size_t TMPLT_ENTRY_SIZE = 32; /* 8 x 4 bytes */
	static constexpr size_t TMPLT_COUNT = 7;

	oab_writer w;
	/* OAB_HDR */
	w.put_u32le(OAB_TMPL_VERSION);
	w.put_u32le(0); /* ulSerial: MUST be 0 */
	w.put_u32le(0); /* ulTotRecs: SHOULD be 0 */

	/* 7 TMPLT_ENTRY structures, all zeros (no template data) */
	for (size_t i = 0; i < TMPLT_COUNT * (TMPLT_ENTRY_SIZE / 4); ++i)
		w.put_u32le(0);

	/* NAMES_STRUCT */
	w.put_u8(0); w.put_u8(0); /* cIDsNames (2 bytes) */
	w.put_u8(0); w.put_u8(0); /* cGuids (2 bytes) */
	w.put_u32le(0); /* oIDs */
	w.put_u32le(0); /* oGuids */
	w.put_u32le(0); /* oNames */

	/* address-templates: oot-count = 0 */
	w.put_u32le(0);
	return w.data();
}

namespace {

class OabPlugin {
	public:
	OabPlugin();
	http_status proc(int, const void *, uint64_t);
	static BOOL preproc(int);
	void clear_cache();

	private:
	http_status send_response(int ctx_id, const char *ct_type, const std::string &body);
	http_status send_error(int ctx_id, http_status);
	http_status serve_manifest(int ctx_id, int32_t base_id);
	http_status serve_lzx(int ctx_id, int32_t base_id, uint32_t seq);
	http_status serve_tmpl(int ctx_id, int32_t base_id, uint32_t seq);
	const oab_cache_entry *get_or_generate(int32_t base_id);
	std::string generate_uc(int32_t base_id, uint32_t seq, const std::string &guid, const std::string &oab_dn);
	bool generate_oab(int32_t base_id, oab_cache_entry &entry);

	std::mutex m_cache_lock;
	std::unordered_map<int32_t, oab_cache_entry> m_cache;
	std::string m_org_name;
	std::chrono::seconds m_cache_interval{300};
};

} /* anonymous namespace */

DECLARE_HPM_API(,);

static constexpr cfg_directive oab_nsp_cfg_defaults[] = {
	{"cache_interval", "5min", CFG_TIME, "1s", "1d"},
	{"x500_org_name", "Gromox default"},
	CFG_TABLE_END,
};

OabPlugin::OabPlugin()
{
	auto cfg = config_file_initd("exchange_nsp.cfg", get_config_path(),
	           oab_nsp_cfg_defaults);
	if (cfg != nullptr) {
		auto v = cfg->get_value("X500_ORG_NAME");
		if (v != nullptr)
			m_org_name = v;
		auto ci = cfg->get_ll("cache_interval");
		if (ci > 0)
			m_cache_interval = std::chrono::seconds(ci);
	}
	if (m_org_name.empty())
		m_org_name = "Gromox default";
}

BOOL OabPlugin::preproc(int ctx_id)
{
	auto req = get_request(ctx_id);
	return strncasecmp(req->f_request_uri.c_str(), "/OAB/", 5) == 0 ? TRUE : false;
}

/**
 * Look for "<seq>.lzx" and extract the sequence number.
 */
static unsigned int parse_seq_path(const char *s)
{
	char *end = nullptr;
	auto seq = strtoul(s, &end, 10);
	if (end == nullptr || end == s || strcmp(end, ".lzx") != 0)
		return 0;
	return seq;
}

/**
 * Look for "lng<lcid>-<seq>.lzx" and extract the parts.
 */
static unsigned int parse_template_path(const char *s)
{
	if (strncmp(s, "lng", 3) != 0)
		return 0;
	char *end = nullptr;
	s += 3;
	strtoul(s, &end, 10); /* LCID */
	if (end == nullptr || end == s || *end != '-')
		return 0;
	s = end + 1;
	auto seq = strtoul(s, &end, 10);
	if (end == s || strcmp(end, ".lzx") != 0)
		return 0;
	return seq;
}

http_status OabPlugin::proc(int ctx_id, const void *content, uint64_t len) try
{
	HTTP_AUTH_INFO auth_info = get_auth_info(ctx_id);
	if (auth_info.auth_status != http_status::ok)
		return http_status::unauthorized;

	/* Resolve username -> domain -> base_id */
	auto pdomain = strchr(auth_info.username, '@');
	if (pdomain == nullptr)
		return send_error(ctx_id, http_status::bad_request);
	pdomain++;

	unsigned int domain_id = 0, org_id = 0;
	if (!mysql_adaptor_get_domain_ids(pdomain, &domain_id, &org_id)) {
		mlog(LV_WARN, "oab: domain %s not found", pdomain);
		return send_error(ctx_id, http_status::not_found);
	}
	int32_t base_id = org_id == 0 ? -domain_id : org_id;

	/*
	 * Parse URI: /OAB/oab.xml
	 *            /OAB/<seq>.lzx
	 *            /OAB/lng<lcid>-<seq>.lzx
	 */
	auto req = get_request(ctx_id);
	const auto &uri = req->f_request_uri;

	if (strcasecmp(&uri[5], "oab.xml") == 0)
		return serve_manifest(ctx_id, base_id);
	auto seq = parse_seq_path(&uri[5]);
	if (seq != 0)
		return serve_lzx(ctx_id, base_id, seq);
	seq = parse_template_path(&uri[5]);
	if (seq != 0)
		return serve_tmpl(ctx_id, base_id, seq);

	return send_error(ctx_id, http_status::not_found);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2092: ENOMEM");
	return http_status::none;
}

http_status OabPlugin::send_response(int ctx_id,
	const char *content_type, const std::string &body)
{
	auto hdr = fmt::format(
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: {}\r\n"
		"Content-Length: {}\r\n\r\n",
		content_type, body.size());
	auto wr = write_response(ctx_id, hdr.data(), hdr.size());
	if (wr != http_status::ok)
		return wr;
	return write_response(ctx_id, body.data(), body.size());
}

http_status OabPlugin::send_error(int ctx_id, http_status code)
{
	const char *text = "Error";
	unsigned int icode = 500;
	switch (code) {
	case http_status::bad_request:
		text = "Bad Request"; icode = 400; break;
	case http_status::not_found:
		text = "Not Found"; icode = 404; break;
	default:
		break;
	}
	auto body = fmt::format("{} {}", icode, text);
	auto hdr = fmt::format(
		"HTTP/1.1 {} {}\r\n"
		"Content-Type: text/plain\r\n"
		"Content-Length: {}\r\n\r\n",
		icode, text, body.size());
	auto wr = write_response(ctx_id, hdr.data(), hdr.size());
	if (wr != http_status::ok)
		return wr;
	return write_response(ctx_id, body.data(), body.size());
}

const oab_cache_entry *OabPlugin::get_or_generate(int32_t base_id)
{
	std::lock_guard lock(m_cache_lock);
	auto it = m_cache.find(base_id);
	auto now = std::chrono::steady_clock::now();
	if (it != m_cache.end() &&
	    now - it->second.gen_time < m_cache_interval)
		return &it->second;

	/* Generate fresh data */
	oab_cache_entry entry;
	if (it != m_cache.end())
		entry.sequence = it->second.sequence + 1;
	if (!generate_oab(base_id, entry))
		return nullptr;
	entry.gen_time = now;
	auto &ref = m_cache[base_id] = std::move(entry);
	return &ref;
}

http_status OabPlugin::serve_manifest(int ctx_id, int32_t base_id)
{
	auto entry = get_or_generate(base_id);
	if (entry == nullptr)
		return send_error(ctx_id, http_status::not_found);
	return send_response(ctx_id, "text/xml", entry->manifest_xml);
}

http_status OabPlugin::serve_lzx(int ctx_id, int32_t base_id, uint32_t seq)
{
	auto entry = get_or_generate(base_id);
	if (entry == nullptr || entry->sequence != seq)
		return send_error(ctx_id, http_status::not_found);
	return send_response(ctx_id, "application/octet-stream", entry->lzx_data);
}

http_status OabPlugin::serve_tmpl(int ctx_id, int32_t base_id, uint32_t seq)
{
	auto entry = get_or_generate(base_id);
	if (entry == nullptr || entry->sequence != seq)
		return send_error(ctx_id, http_status::not_found);
	return send_response(ctx_id, "application/octet-stream", entry->tmpl_lzx_data);
}

/**
 * Procedure for MS-OXOAB v16 §2.9
 * "Uncompressed OAB Version 4 Full Details File"
 */
std::string OabPlugin::generate_uc(int32_t base_id, uint32_t sequence,
    const std::string &guid_str, const std::string &oab_dn)
{
	auto pbase = ab_tree::AB.get(base_id);
	if (pbase == nullptr) {
		mlog(LV_WARN, "oab: ab_tree base_id %d not available", base_id);
		return {};
	}
	const auto &base = *pbase;

	/* Count GAL-visible users */
	size_t user_count = base.filtered_user_count();

	oab_writer w;

	/* OAB_HDR (12 bytes, MS-OXOAB §2.9.1) */
	w.put_u32le(OAB_V4_VERSION);
	auto serial_off = w.size();
	w.put_u32le(0); // placeholder for ulSerial (CRC32 of rest of file)
	w.put_u32le(user_count);

	/* OAB_META_DATA (MS-OXOAB §2.9.2): cbSize includes itself */
	auto meta_off = w.begin_record();

	/* rgHdrAtts: OAB_PROP_TABLE for header record */
	w.put_u32le(HDR_PROP_COUNT);
	for (size_t i = 0; i < HDR_PROP_COUNT; ++i) {
		w.put_u32le(hdr_props[i]);
		w.put_u32le(hdr_flags[i]);
	}

	/* rgOabAtts: OAB_PROP_TABLE for object records */
	w.put_u32le(OBJ_PROP_COUNT);
	for (size_t i = 0; i < OBJ_PROP_COUNT; ++i) {
		w.put_u32le(obj_props[i]);
		w.put_u32le(obj_flags[i]);
	}

	w.end_record(meta_off);

	/* Header record (OAB_V4_REC, MS-OXOAB §2.9.4) */
	{
		auto rec_off = w.begin_record();
		// Presence bit array: 4 props -> ceil(4/8)=1 byte
		// MSB = prop 0; all 4 present -> 0xF0
		w.put_u8(0xF0);

		// Prop 0: PidTagOfflineAddressBookName (PT_UNICODE)
		w.put_str("\\Global Address List");
		// Prop 1: PidTagOfflineAddressBookDistinguishedName (PT_STRING8)
		w.put_str(oab_dn);
		// Prop 2: PidTagOfflineAddressBookSequence (PT_LONG)
		w.put_varui(sequence);
		// Prop 3: PidTagOfflineAddressBookContainerGuid (PT_STRING8)
		w.put_str(guid_str);

		w.end_record(rec_off);
	}

	/* Object records (one OAB_V4_REC per GAL-visible entry) */
	for (auto it = base.ufbegin(); it != base.ufend(); ++it) {
		auto mid = *it;
		auto rec_off = w.begin_record();

		/* Collect property values */
		std::string dn_val, smtp_val;

		bool has_dn   = base.dn(mid, dn_val);
		auto smtp_ptr = base.user_info(mid, userinfo::mail_address);
		if (smtp_ptr != nullptr)
			smtp_val = smtp_ptr;

		auto display_val      = base.displayname(mid);
		auto etyp_val         = base.etyp(mid);
		uint32_t obj_type_val = etyp_to_objtype(etyp_val);
		uint32_t dtyp_val     = base.dtyp(mid);
		auto dtypx_opt        = base.dtypx(mid);
		uint32_t dtypx_val    = dtypx_opt.value_or(0);
		bool has_dtypx        = dtypx_opt.has_value();

		std::string given_val, surname_val, title_val, dept_val;
		std::string company_val, office_val, phone_val;

		base.fetch_prop(mid, PR_GIVEN_NAME, given_val);
		base.fetch_prop(mid, PR_SURNAME, surname_val);
		base.fetch_prop(mid, PR_TITLE, title_val);
		base.fetch_prop(mid, PR_DEPARTMENT_NAME, dept_val);
		base.company_name(mid, company_val);
		base.office_location(mid, office_val);
		base.fetch_prop(mid, PR_BUSINESS_TELEPHONE_NUMBER, phone_val);

		/*
		 * Build presence bit array (14 props -> ceil(14/8) = 2 bytes)
		 * MSB of first byte = prop 0, bit 6 = prop 1, ...
		 * Per MS-OXOAB: empty strings MUST NOT be encoded;
		 * mark absent in presence bits instead.
		 */
		uint8_t presence[2] = {0, 0};
		if (has_dn && !dn_val.empty())      presence[0] |= 0x80; // prop 0
		if (!smtp_val.empty())              presence[0] |= 0x40; // prop 1
		if (!display_val.empty())           presence[0] |= 0x20; // prop 2
		presence[0] |= 0x10; // prop 3: object type (always present)
		presence[0] |= 0x08; // prop 4: display type (always present)
		if (has_dtypx)                      presence[0] |= 0x04; // prop 5
		if (!given_val.empty())             presence[0] |= 0x02; // prop 6
		if (!surname_val.empty())           presence[0] |= 0x01; // prop 7
		if (!title_val.empty())             presence[1] |= 0x80; // prop 8
		if (!dept_val.empty())              presence[1] |= 0x40; // prop 9
		if (!company_val.empty())           presence[1] |= 0x20; // prop 10
		if (!office_val.empty())            presence[1] |= 0x10; // prop 11
		if (!phone_val.empty())             presence[1] |= 0x08; // prop 12
		// prop 13: PidTagOfflineAddressBookTruncatedProperties - always absent

		w.put_u8(presence[0]);
		w.put_u8(presence[1]);

		/* Write present property values in schema order */
		if (presence[0] & 0x80) w.put_str(dn_val);
		if (presence[0] & 0x40) w.put_str(smtp_val);
		if (presence[0] & 0x20) w.put_str(display_val);
		w.put_varui(obj_type_val);  // always present
		w.put_varui(dtyp_val);      // always present
		if (presence[0] & 0x04) w.put_varui(dtypx_val);
		if (presence[0] & 0x02) w.put_str(given_val);
		if (presence[0] & 0x01) w.put_str(surname_val);
		if (presence[1] & 0x80) w.put_str(title_val);
		if (presence[1] & 0x40) w.put_str(dept_val);
		if (presence[1] & 0x20) w.put_str(company_val);
		if (presence[1] & 0x10) w.put_str(office_val);
		if (presence[1] & 0x08) w.put_str(phone_val);

		w.end_record(rec_off);
	}

	/* Patch ulSerial: CRC32 of everything after the 12-byte OAB_HDR */
	auto &raw   = w.data();
	auto serial = crc32_oab(&raw[12], raw.size() - 12);
	w.patch_u32le(serial_off, serial);
	mlog(LV_INFO, "oab: generated OABv4 for base_id %d: %zu users, %zu bytes",
		static_cast<int>(base_id), user_count, raw.size());
	return std::move(w.data());
}

/**
 * Procedure for MS-OXOAB v16 §2.11 "Compressed OAB Version 4 Details File"
 */
bool OabPlugin::generate_oab(int32_t base_id, oab_cache_entry &entry)
{
	auto guid_str = deterministic_guid(base_id);
	/*
	 * MS-OXOAB: PidTagOfflineAddressBookDistinguishedName
	 * is the DN of the address list, not the OAB object.
	 * For the GAL, Exchange uses "/" (the root).
	 */
	std::string oab_dn = "/";
	auto raw = generate_uc(base_id, entry.sequence, guid_str, oab_dn);
	if (raw.empty())
		return false;
	entry.lzx_data = oab_wrap_lzx(raw, 3);

	/* Generate and compress display template (MS-OXOAB 2.2) */
	auto tmpl_raw = generate_template_raw();
	entry.tmpl_lzx_data = oab_wrap_lzx(tmpl_raw, 3);

	auto data_sha = sha1_hex(entry.lzx_data);
	auto tmpl_sha = sha1_hex(entry.tmpl_lzx_data);
	auto data_file = fmt::format("{}.lzx", entry.sequence);
	auto tmpl_file = fmt::format("lng0409-{}.lzx", entry.sequence);

	/* Generate manifest XML (MS-OXWOAB) */
	tinyxml2::XMLDocument doc;
	doc.InsertEndChild(doc.NewDeclaration());
	auto root = doc.NewElement("OAB");
	doc.InsertEndChild(root);

	auto oal = doc.NewElement("OAL");
	oal->SetAttribute("id", guid_str.c_str());
	oal->SetAttribute("dn", oab_dn.c_str());
	oal->SetAttribute("name", "\\Global Address List");
	root->InsertEndChild(oal);

	auto full = doc.NewElement("Full");
	full->SetAttribute("seq", entry.sequence);
	full->SetAttribute("ver", OAB_V4_VERSION);
	full->SetAttribute("size", entry.lzx_data.size());
	full->SetAttribute("uncompressedsize", raw.size());
	full->SetAttribute("SHA", data_sha.c_str());
	full->SetText((std::to_string(entry.sequence) + ".lzx").c_str());
	oal->InsertEndChild(full);

	auto tmpl = doc.NewElement("Template");
	tmpl->SetAttribute("seq", entry.sequence);
	tmpl->SetAttribute("ver", OAB_TMPL_VERSION);
	tmpl->SetAttribute("size", entry.tmpl_lzx_data.size());
	tmpl->SetAttribute("uncompressedsize", tmpl_raw.size());
	tmpl->SetAttribute("SHA", tmpl_sha.c_str());
	tmpl->SetAttribute("langid", "0409");
	tmpl->SetAttribute("type", "windows");
	tmpl->SetText(tmpl_file.c_str());
	oal->InsertEndChild(tmpl);

	tinyxml2::XMLPrinter printer(nullptr, true);
	doc.Print(&printer);
	entry.manifest_xml.assign(printer.CStr(), printer.CStrSize() > 0 ?
	                          printer.CStrSize() - 1 : 0);
	return true;
}

void OabPlugin::clear_cache()
{
	std::lock_guard lock(m_cache_lock);
	m_cache.clear();
}

///////////////////////////////////////////////////////////////////////////////
// Plugin management

static std::unique_ptr<OabPlugin> g_oab_plugin;

static BOOL oab_init(const struct dlfuncs &apidata)
{
	LINK_HPM_API(apidata)
	if (service_run_library({"libgxs_mysql_adaptor.so",
	    SVC_mysql_adaptor}) != PLUGIN_LOAD_OK)
		return false;

	/* Initialize ab_tree (shared with NSP; init is idempotent per running count) */
	auto cfg = config_file_initd("exchange_nsp.cfg", get_config_path(),
	           oab_nsp_cfg_defaults);
	if (cfg != nullptr) {
		auto org = cfg->get_value("X500_ORG_NAME");
		auto ci = cfg->get_ll("cache_interval");
		if (ab_tree::AB.init(org != nullptr ? org : "Gromox default",
		    ci > 0 ? ci : 300) != 0)
			return false;
	} else {
		if (ab_tree::AB.init("Gromox default", 300) != 0)
			return false;
	}
	if (!ab_tree::AB.run()) {
		mlog(LV_ERR, "oab: failed to start ab_tree");
		return false;
	}

	HPM_INTERFACE ifc{};
	ifc.preproc = &OabPlugin::preproc;
	ifc.proc    = [](int ctx, const void *cont, uint64_t len) { return g_oab_plugin->proc(ctx, cont, len); };
	ifc.retr    = [](int ctx) { return HPM_RETRIEVE_DONE; };
	ifc.term    = [](int ctx) {};
	if (!register_interface(&ifc))
		return false;
	try {
		g_oab_plugin.reset(new OabPlugin());
	} catch (const std::exception &e) {
		mlog(LV_ERR, "oab: failed to initialize: %s", e.what());
		return false;
	}
	return TRUE;
}

BOOL HPM_oab(enum plugin_op reason, const struct dlfuncs &data)
{
	if (reason == PLUGIN_INIT) {
		return oab_init(data);
	} else if (reason == PLUGIN_FREE) {
		g_oab_plugin.reset();
		ab_tree::AB.stop();
		return TRUE;
	} else if (reason == PLUGIN_RELOAD) {
		ab_tree::AB.invalidate_cache();
		if (g_oab_plugin)
			g_oab_plugin->clear_cache();
		return TRUE;
	}
	return TRUE;
}
