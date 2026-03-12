// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <gromox/defs.h>

struct GX_EXPORT MITEM {
	std::string mid;
	int id = 0, uid = 0;
	char flag_bits = 0;
	uint32_t digest_off = 0, digest_len = 0;
};

/**
 * Two-way indexed message set.
 * @m_vec:	index from seqid -> MITEM
 * @m_hash:	index from imapuid -> seqid
 * @m_dpool:	contiguous storage for all digest JSON strings;
 *		kept as one allocation so it is returned to the OS
 *		in a single munmap rather than stuck in allocator bins
 */
struct GX_EXPORT XARRAY {
	std::vector<MITEM> m_vec;
	std::unordered_map<unsigned int, size_t> m_hash;
	std::string m_dpool;

	int append(MITEM &&, unsigned int tag);
	MITEM *get_item(size_t idx) {
		return idx < m_vec.size() ? &m_vec[idx] : nullptr;
	}
	MITEM *get_itemx(unsigned int tag) {
		auto i = m_hash.find(tag);
		return i != m_hash.end() ? &m_vec[i->second] : nullptr;
	}
	std::string_view get_digest(const MITEM &m) const {
		return {m_dpool.data() + m.digest_off, m.digest_len};
	}
	void remove(const MITEM *m) {
		m_hash.erase(m->uid);
		m_vec.erase(m_vec.begin() + m->id - 1);
	}
	inline size_t get_capacity() const { return m_vec.size(); }
	void clear();
};
