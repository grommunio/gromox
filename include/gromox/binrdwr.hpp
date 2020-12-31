// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <gromox/defs.h>
#include <gromox/fileio.h>

namespace gromox {

class GX_EXPORT lb_reader { /* a little-endian binary reader */
	public:
	struct exception : public std::runtime_error { using std::runtime_error::runtime_error; };
	struct eof : public exception {
		eof() : exception("EOF") {}
	};
	struct invalid : public exception {
		invalid() : exception("No detail") {}
		invalid(const char *s) : exception(s != nullptr ? s : "No detail") {}
	};

	lb_reader(const void *data, size_t z) :
		m_data(static_cast<const char *>(data)), m_ptr(m_data), m_len(z)
	{}

	const char *read(size_t n)
	{
		if (m_ptr - m_data + n > m_len)
			throw eof();
		auto ret = m_ptr;
		m_ptr += n;
		return ret;
	}

	std::string readustr(size_t n)
	{
		return iconvtext(read(n * sizeof(char16_t)), n * sizeof(char16_t), "UTF-16LE", "UTF-8");
	}

	const char *pread(size_t offset, size_t n) const
	{
		if (offset + n > m_len)
			throw eof();
		return &m_data[offset];
	}

	std::string preadstr(size_t offset) const
	{
		if (offset >= m_len)
			throw eof();
		return std::string(&m_data[offset], strnlen(&m_data[offset], m_len - offset));
	}

	std::string preadustr(size_t offset) const;

	uint8_t r1()
	{
		uint8_t v;
		if (m_ptr - m_data + sizeof(v) > m_len)
			throw eof();
		memcpy(&v, m_ptr, sizeof(v));
		m_ptr += sizeof(v);
		return v;
	}

	uint16_t r2()
	{
		uint16_t v;
		if (m_ptr - m_data + sizeof(v) > m_len)
			throw eof();
		memcpy(&v, m_ptr, sizeof(v));
		v = le16_to_cpu(v);
		m_ptr += sizeof(v);
		return v;
	}

	uint32_t r4()
	{
		uint32_t v;
		if (m_ptr - m_data + sizeof(v) > m_len)
			throw eof();
		memcpy(&v, m_ptr, sizeof(v));
		v = le32_to_cpu(v);
		m_ptr += sizeof(v);
		return v;
	}

	double rdbl()
	{
		double v;
		if (m_ptr - m_data + sizeof(v) > m_len)
			throw eof();
		memcpy(&v, m_ptr, sizeof(v));
		m_ptr += sizeof(v);
		return v;
	}

	/* Pull a variable-sized 1B/2B integer */
	uint16_t rlen()
	{
		auto v = r1();
		if (v == 0xFF)
			v = le16_to_cpu(r2());
		return v;
	}

	/* Pull/assert the next 1B/2B/4B integer is a certain value */
	void x1(uint8_t exp, const char *s = nullptr)
	{
		if (r1() != exp)
			throw invalid(s);
	}

	void x2(uint16_t exp, const char *s = nullptr)
	{
		if (r2() != exp)
			throw invalid(s);
	}

	void x4(uint32_t exp, const char *s = nullptr)
	{
		if (r4() != exp)
			throw invalid(s);
	}

	protected:
	const char *m_data = nullptr, *m_ptr = nullptr;
	size_t m_len = 0;
};

struct GX_EXPORT lb_writer {
	public:
	void w1(uint8_t v)
	{
		m_data.append(reinterpret_cast<const char *>(&v), sizeof(v));
	}

	void w2(uint16_t v)
	{
		v = cpu_to_le16(v);
		m_data.append(reinterpret_cast<const char *>(&v), sizeof(v));
	}

	void w4(uint32_t v)
	{
		v = cpu_to_le32(v);
		m_data.append(reinterpret_cast<const char *>(&v), sizeof(v));
	}

	void wdbl(double v)
	{
		m_data.append(reinterpret_cast<const char *>(&v), sizeof(v));
	}

	void write(const void *v, size_t z)
	{
		m_data.append(reinterpret_cast<const char *>(v), z);
	}

	void wlen(uint16_t len)
	{
		if (len >= 255) {
			len = cpu_to_le16(len);
			m_data.append(reinterpret_cast<const char *>(&len), len);
		} else {
			uint8_t l8 = len;
			m_data.append(reinterpret_cast<const char *>(&l8), sizeof(l8));
		}
	}

	void wustr(const char *utf8)
	{
		auto utf16 = iconvtext(utf8, strlen(utf8), "UTF-8", "UTF-16LE");
		wlen(utf16.size());
		write(utf16.c_str(), utf16.size() * sizeof(utf16[0]));
	}

	std::string m_data;
};

} /* namespace */
