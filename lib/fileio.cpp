// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2020 grommunio GmbH
// This file is part of Gromox.
#define _GNU_SOURCE 1
#include <cstring>
#include <string>
#include <gromox/binrdwr.hpp>
#include <gromox/util.hpp>

using namespace std::string_literals;

namespace gromox {

std::string lb_reader::preadustr(size_t offset) const
{
	std::u16string tmp;
	do {
		if (offset >= m_len)
			throw eof();
		char16_t c;
		memcpy(&c, &m_data[offset], sizeof(c));
		if (c == 0)
			break;
		tmp += c;
		offset += 2;
	} while (true);
	return iconvtext(reinterpret_cast<const char *>(tmp.data()),
	       tmp.size() * sizeof(char16_t), "UTF-16LE", "UTF-8");
}

} /* namespace */
