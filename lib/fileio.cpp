// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2020 grommunio GmbH
// This file is part of Gromox.
#include <cmath>
#include <cstring>
#include <string>
#include <iconv.h>
#include <gromox/binrdwr.hpp>
#include <gromox/scope.hpp>
#include <gromox/rop_util.hpp>

using namespace std::string_literals;

namespace gromox {

/**
 * This function gives an approximation only, and it is only used for debug
 * prints because of that. apptimes are timezoneless, so the conversion to
 * nttime is necessarily off by as much as timezone you are on.
 */
uint64_t apptime_to_nttime_approx(double v)
{
	uint64_t s = std::modf(v, &v) * 86400;
	uint64_t d = v;
	s += 9435312000;
	if (d < 61)
		s += 86400;
	s += d * 86400;
	s *= 10000000;
	return s;
}

std::string iconvtext(const char *src, size_t src_size,
    const char *from, const char *to)
{
	if (strcasecmp(from, to) == 0)
		return {reinterpret_cast<const char *>(src), src_size};
	auto cd = iconv_open((to + "//IGNORE"s).c_str(), from);
	if (cd == reinterpret_cast<iconv_t>(-1))
		return "UNKNOWN_CHARSET";
	auto cleanup = make_scope_exit([&]() { iconv_close(cd); });
	char buffer[4096];
	std::string out;

	while (src_size > 0) {
		auto dst = buffer;
		size_t dst_size = sizeof(buffer);
		auto ret = iconv(cd, (char**)&src, &src_size, (char**)&dst, &dst_size);
		if (ret != static_cast<size_t>(-1) || dst_size != sizeof(buffer)) {
			out.append(buffer, sizeof(buffer) - dst_size);
			continue;
		}
		if (src_size > 0) {
			--src_size;
			++src;
		}
		out.append(buffer, sizeof(buffer) - dst_size);
	}
	return out;
}

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
