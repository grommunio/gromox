// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#pragma once
#include <atomic>
#include <string>
#include <unordered_map>
#include <vector>
#include <json/value.h>

struct MITEM {
	std::string mid;
	int id = 0, uid = 0;
	char flag_bits = 0;
	Json::Value digest;
};

/**
 * Two-way indexed message set.
 * @m_vec:	index from seqid -> MITEM
 * @m_hash:	index from imapuid -> MITEM
 *
 * To keep XARRAY move-assignable, m_limit is a pointer.
 */
struct GX_EXPORT XARRAY {
	XARRAY(std::atomic<size_t> &m) : m_limit(&m) {}
	~XARRAY();

	std::vector<MITEM> m_vec;
	std::unordered_map<unsigned int, size_t> m_hash;
	std::atomic<size_t> *m_limit = nullptr;

	int append(MITEM &&, unsigned int tag);
	MITEM *get_item(size_t idx) {
		return idx < m_vec.size() ? &m_vec[idx] : nullptr;
	}
	MITEM *get_itemx(unsigned int tag) {
		auto i = m_hash.find(tag);
		return i != m_hash.end() ? &m_vec[i->second] : nullptr;
	}
	void remove(const MITEM *m) {
		m_hash.erase(m->uid);
		m_vec.erase(m_vec.begin() + m->id - 1);
	}
	inline size_t get_capacity() const { return m_vec.size(); }
	void clear();
};
