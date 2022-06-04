// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#pragma once
#include <atomic>
#include <unordered_map>
#include <vector>
#include <gromox/mem_file.hpp>
#include <gromox/single_list.hpp>

struct MITEM {
	SINGLE_LIST_NODE node;
	char mid[128];
	int id;
	int uid;
	char flag_bits;
	MEM_FILE f_digest;
};

struct GX_EXPORT XARRAY {
	XARRAY(std::atomic<size_t> &m) : m_limit(m) {}

	std::vector<MITEM> m_vec;
	std::unordered_map<unsigned int, size_t> m_hash;
	std::atomic<size_t> &m_limit;

	int append(MITEM &&, unsigned int tag);
	MITEM *get_item(size_t idx) {
		return idx < m_vec.size() ? &m_vec[idx] : nullptr;
	}
	MITEM *get_itemx(unsigned int tag) {
		auto i = m_hash.find(tag);
		return i != m_hash.end() ? &m_vec[i->second] : nullptr;
	}
	inline size_t get_capacity() const { return m_vec.size(); }
	void clear();
};
