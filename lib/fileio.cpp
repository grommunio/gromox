// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2020 grommunio GmbH
// This file is part of Gromox.
#define _GNU_SOURCE 1
#include <cmath>
#include <cstring>
#include <iconv.h>
#include <string>
#include <string_view>
#include <unistd.h>
#include <zstd.h>
#if defined(__linux__) && defined(__GLIBC__) && __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
#	include <sys/syscall.h>
#endif
#include <gromox/binrdwr.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>

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

unsigned long gx_gettid()
{
#if defined(__linux__) && defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 30))
	return gettid();
#elif defined(__linux__)
	return syscall(SYS_gettid);
#elif defined(__OpenBSD__)
	return getthrid();
#else
	return (unsigned long)pthread_self();
#endif
}

std::string zstd_decompress(std::string_view x)
{
	std::string out;
	while (x.size() > 0) {
		char buf[4096];
		auto ret = ZSTD_decompress(buf, arsizeof(buf), x.data(), x.size());
		if (ZSTD_isError(ret))
			break;
		out.append(buf, ret);
		x.remove_prefix(ret);
	}
	return out;
}

std::string base64_decode(const std::string_view &x)
{
	std::string out;
	out.resize(x.size());
	size_t final_size = 0;
	int ret = decode64_ex(x.data(), x.size(), out.data(), x.size(), &final_size);
	if (ret < 0)
		out.clear();
	else
		out.resize(final_size);
	return out;
}

} /* namespace */
