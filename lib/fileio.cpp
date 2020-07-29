#include <cstring>
#include <string>
#include <iconv.h>
#include <gromox/binrdwr.hpp>
#include <gromox/scope.hpp>

using namespace std::string_literals;

namespace gromox {

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
