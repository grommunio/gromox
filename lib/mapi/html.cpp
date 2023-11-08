// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cassert>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iconv.h>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <libHX/libxml_helper.h>
#include <libxml/HTMLparser.h>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/int_hash.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#define QRF(expr) do { if (pack_result{expr} != EXT_ERR_SUCCESS) return ecError; } while (false)
#define ERF(expr) do { ec_error_t klfdv{expr}; if (klfdv != ecSuccess) return klfdv; } while (false)
#define RTF_PARAGRAPHALIGN_DEFAULT			0
#define RTF_PARAGRAPHALIGN_LEFT				1
#define RTF_PARAGRAPHALIGN_CENTER			2
#define RTF_PARAGRAPHALIGN_RIGHT			3
#define RTF_PARAGRAPHALIGN_JUSTIFY			4

#define MAX_TABLE_ITEMS						1024

using namespace gromox;

namespace {

using rgb_t = unsigned int;

struct RTF_WRITER {
	RTF_WRITER();
	~RTF_WRITER();
	EXT_PUSH ext_push{};
	std::map<std::string, unsigned int> pfont_hash /* font -> index */;
	std::map<rgb_t, unsigned int> pcolor_hash; /* color -> index */
	std::vector<rgb_t> colors_ordered; /* index -> color */
	std::vector<std::string> fonts_ordered; /* index -> font */
	iconv_t cd;
};

enum class htag : uint8_t {
	center, div, em, font, h1, h2, h3, h4, h5, h6, hr, i, li, mark, none, a,
	b, br, ol, p, s, script, span, style, sub, sup, table, td, th, tr, ul,
};

static constexpr struct tagentry {
	const char name[7];
	enum htag tag;
} htmltags[] = {
	{"a", htag::a},
	{"b", htag::b},
	{"br", htag::br},
	{"center", htag::center},
	{"div", htag::div},
	{"em", htag::em},
	{"font", htag::font},
	{"h1", htag::h1},
	{"h2", htag::h2},
	{"h3", htag::h3},
	{"h4", htag::h4},
	{"h5", htag::h5},
	{"h6", htag::h6},
	{"hr", htag::hr},
	{"i", htag::i},
	{"li", htag::li},
	{"mark", htag::mark},
	{"ol", htag::ol},
	{"p", htag::p},
	{"s", htag::s},
	{"script", htag::script},
	{"span", htag::span},
	{"style", htag::style},
	{"sub", htag::sub},
	{"sup", htag::sup},
	{"table", htag::table},
	{"td", htag::td},
	{"th", htag::th},
	{"tr", htag::tr},
	{"ul", htag::ul},
};

}

static ec_error_t html_enum_write(RTF_WRITER *, const xmlNode *);

static inline iconv_t html_iconv_open()
{
	return iconv_open("UTF-16LE", "UTF-8");
}

RTF_WRITER::RTF_WRITER() : cd(html_iconv_open())
{}

RTF_WRITER::~RTF_WRITER()
{
	if (cd != (iconv_t)-1)
		iconv_close(cd);
}

	static constexpr std::pair<const char *, rgb_t> color_map[] = {
		{"aliceblue",			0xf0f8ff},
		{"antiquewhite",		0xfaebd7},
		{"aqua",				0x00ffff},
		{"aquamarine",			0x7fffd4},
		{"azure",				0xf0ffff},
		{"beige",				0xf5f5dc},
		{"bisque",				0xffe4c4},
		{"black",				0x000000},
		{"blanchedalmond",		0xffebcd},
		{"blue",				0x0000ff},
		{"blueviolet",			0x8a2be2},
		{"brown",				0xa52a2a},
		{"burlywood",			0xdeb887},
		{"cadetblue",			0x5f9ea0},
		{"chartreuse",			0x7fff00},
		{"chocolate",			0xd2691e},
		{"coral",				0xff7f50},
		{"cornflowerblue",		0x6495ed},
		{"cornsilk",			0xfff8dc},
		{"crimson",				0xdc143c},
		{"cyan",				0x00ffff},
		{"darkblue",			0x00008b},
		{"darkcyan",			0x008b8b},
		{"darkgoldenrod",		0xb8860b},
		{"darkgray",			0xa9a9a9},
		{"darkgreen",			0x006400},
		{"darkgrey",			0xa9a9a9},
		{"darkkhaki",			0xbdb76b},
		{"darkmagenta",			0x8b008b},
		{"darkolivegreen",		0x556b2f},
		{"darkorange",			0xff8c00},
		{"darkorchid",			0x9932cc},
		{"darkred",				0x8b0000},
		{"darksalmon",			0xe9967a},
		{"darkseagreen",		0x8fbc8f},
		{"darkslateblue",		0x483d8b},
		{"darkslategray",		0x2f4f4f},
		{"darkslategrey",		0x2f4f4f},
		{"darkturquoise",		0x00ced1},
		{"darkviolet",			0x9400d3},
		{"deeppink",			0xff1493},
		{"deepskyblue",			0x00bfff},
		{"dimgray",				0x696969},
		{"dimgrey",				0x696969},
		{"dodgerblue",			0x1e90ff},
		{"firebrick",			0xb22222},
		{"floralwhite",			0xfffaf0},
		{"forestgreen",			0x228b22},
		{"fuchsia",				0xff00ff},
		{"gainsboro",			0xdcdcdc},
		{"ghostwhite",			0xf8f8ff},
		{"gold",				0xffd700},
		{"goldenrod",			0xdaa520},
		{"gray",				0x808080},
		{"green",				0x008000},
		{"greenyellow",			0xadff2f},
		{"grey",				0x808080},
		{"honeydew",			0xf0fff0},
		{"hotpink",				0xff69b4},
		{"indianred",			0xcd5c5c},
		{"indigo",				0x4b0082},
		{"ivory",				0xfffff0},
		{"khaki",				0xf0e68c},
		{"lavender",			0xe6e6fa},
		{"lavenderblush",		0xfff0f5},
		{"lawngreen",			0x7cfc00},
		{"lemonchiffon",		0xfffacd},
		{"lightblue",			0xadd8e6},
		{"lightcoral",			0xf08080},
		{"lightcyan",			0xe0ffff},
		{"lightgoldenrodyellow",0xfafad2},
		{"lightgray",			0xd3d3d3},
		{"lightgreen",			0x90ee90},
		{"lightgrey",			0xd3d3d3},
		{"lightpink",			0xffb6c1},
		{"lightsalmon",			0xffa07a},
		{"lightseagreen",		0x20b2aa},
		{"lightskyblue",		0x87cefa},
		{"lightslategray",		0x778899},
		{"lightslategrey",		0x778899},
		{"lightsteelblue",		0xb0c4de},
		{"lightyellow",			0xffffe0},
		{"lime",				0x00ff00},
		{"limegreen",			0x32cd32},
		{"linen",				0xfaf0e6},
		{"magenta",				0xff00ff},
		{"maroon",				0x800000},
		{"mediumaquamarine",	0x66cdaa},
		{"mediumblue",			0x0000cd},
		{"mediumorchid",		0xba55d3},
		{"mediumpurple",		0x9370db},
		{"mediumseagreen",		0x3cb371},
		{"mediumslateblue",		0x7b68ee},
		{"mediumspringgreen",	0x00fa9a},
		{"mediumturquoise",		0x48d1cc},
		{"mediumvioletred",		0xc71585},
		{"midnightblue",		0x191970},
		{"mintcream",			0xf5fffa},
		{"mistyrose",			0xffe4e1},
		{"moccasin",			0xffe4b5},
		{"navajowhite",			0xffdead},
		{"navy",				0x000080},
		{"oldlace",				0xfdf5e6},
		{"olive",				0x808000},
		{"olivedrab",			0x6b8e23},
		{"orange",				0xffa500},
		{"orangered",			0xff4500},
		{"orchid",				0xda70d6},
		{"palegoldenrod",		0xeee8aa},
		{"palegreen",			0x98fb98},
		{"paleturquoise",		0xafeeee},
		{"palevioletred",		0xdb7093},
		{"papayawhip",			0xffefd5},
		{"peachpuff",			0xffdab9},
		{"peru",				0xcd853f},
		{"pink",				0xffc0cb},
		{"plum",				0xdda0dd},
		{"powderblue",			0xb0e0e6},
		{"purple",				0x800080},
		{"rebeccapurple",		0x663399},
		{"red",					0xff0000},
		{"rosybrown",			0xbc8f8f},
		{"royalblue",			0x4169e1},
		{"saddlebrown",			0x8b4513},
		{"salmon",				0xfa8072},
		{"sandybrown",			0xf4a460},
		{"seagreen",			0x2e8b57},
		{"seashell",			0xfff5ee},
		{"sienna",				0xa0522d},
		{"silver",				0xc0c0c0},
		{"skyblue",				0x87ceeb},
		{"slateblue",			0x6a5acd},
		{"slategray",			0x708090},
		{"slategrey",			0x708090},
		{"snow",				0xfffafa},
		{"springgreen",			0x00ff7f},
		{"steelblue",			0x4682b4},
		{"tan",					0xd2b48c},
		{"teal",				0x008080},
		{"thistle",				0xd8bfd8},
		{"tomato",				0xff6347},
		{"turquoise",			0x40e0d0},
		{"violet",				0xee82ee},
		{"wheat",				0xf5deb3},
		{"white",				0xffffff},
		{"whitesmoke",			0xf5f5f5},
		{"yellow",				0xffff00},
		{"yellowgreen",			0x9acd32},
	};

ec_error_t html_init_library()
{
	textmaps_init();
	/* Test for availability of converters */
	auto cd = html_iconv_open();
	if (cd == (iconv_t)-1) {
		mlog(LV_ERR, "E-2107: iconv_open: %s", strerror(errno));
		return ecError;
	}
	iconv_close(cd);
	return ecSuccess;
}

static void html_set_fonttable(RTF_WRITER *w, const char *name) try
{
	auto it = w->pfont_hash.find(name);
	if (it != w->pfont_hash.cend())
		return; /* font already present */
	if (w->pfont_hash.size() >= MAX_TABLE_ITEMS)
		return; /* table full */
	assert(w->pfont_hash.size() == w->fonts_ordered.size());
	auto tp = w->pfont_hash.emplace(name, w->pfont_hash.size());
	assert(tp.second);
	try {
		w->fonts_ordered.push_back(name);
	} catch (const std::bad_alloc &) {
		w->pfont_hash.erase(tp.first);
	}
} catch (const std::bad_alloc &) {
}

static int html_get_fonttable(RTF_WRITER *pwriter, const char* font_name)
{
	auto it = pwriter->pfont_hash.find(font_name);
	return it != pwriter->pfont_hash.cend() ? it->second : -1;
}

static void html_set_colortable(RTF_WRITER *w, rgb_t color) try
{ 
	auto it = w->pcolor_hash.find(color);
	if (it != w->pcolor_hash.cend())
		return; /* color already present */
	if (w->pcolor_hash.size() >= MAX_TABLE_ITEMS)
		return; /* table full */
	assert(w->pcolor_hash.size() == w->colors_ordered.size());
	auto tp = w->pcolor_hash.emplace(color, w->pcolor_hash.size());
	assert(tp.second);
	try {
		w->colors_ordered.push_back(color);
	} catch (const std::bad_alloc &) {
		w->pcolor_hash.erase(tp.first);
	}
} catch (const std::bad_alloc &) {
}

static int html_get_colortable(RTF_WRITER *w, rgb_t color)
{
	auto it = w->pcolor_hash.find(color);
	return it != w->pcolor_hash.cend() ? it->second : -1;
}

static ec_error_t html_init_writer(RTF_WRITER *pwriter)
{
	if (!pwriter->ext_push.init(nullptr, 0, 0))
		return ecMAPIOOM;
	html_set_fonttable(pwriter, "Times New Roman");
	html_set_fonttable(pwriter, "Arial");
	/* first item in font table is for symbol */
	html_set_fonttable(pwriter, "symbol");
	/* first item in color table is for anchor link */
	html_set_colortable(pwriter, 0x0645AD);
	return ecSuccess;
} 
 
static std::pair<uint16_t, uint16_t>
html_utf8_to_utf16(iconv_t cd, const char *src, size_t ilen)
{
	std::pair<uint16_t, uint16_t> wchar{};
	auto pin = deconst(src);
	auto pout = reinterpret_cast<char *>(&wchar);
	auto olen = sizeof(wchar);
	iconv(cd, nullptr, nullptr, nullptr, nullptr);
	auto ret = iconv(cd, &pin, &ilen, &pout, &olen);
	if (ret == static_cast<size_t>(-1))
		wchar = {0xFFFD, 0};
	else
		wchar = {le16_to_cpu(wchar.first), le16_to_cpu(wchar.second)};
	return wchar;
}

static ec_error_t html_write_string(RTF_WRITER *pwriter, const char *string)
{
	int tmp_len;
	char tmp_buff[24];
	const char *ptr = string, *pend = string + strlen(string);

	while ('\0' != *ptr) {
		static_assert(UCHAR_MAX <= std::size(utf8_byte_num));
		auto len = utf8_byte_num[static_cast<unsigned char>(*ptr)];
		if (len == 0) {
			++ptr;
			continue;
		}
		if (ptr + len > pend) {
			return ecError;
		}
		if (1 == len && isascii(*ptr)) {
			if ('\\' == *ptr) {
				QRF(pwriter->ext_push.p_bytes("\\\\", 2));
			} else if ('{' == *ptr) {
				QRF(pwriter->ext_push.p_bytes("\\{", 2));
			} else if ('}' == *ptr) {
				QRF(pwriter->ext_push.p_bytes("\\}", 2));
			} else {
				QRF(pwriter->ext_push.p_uint8(*ptr));
			}
			ptr += len;
			continue;
		}
		auto [w1, w2] = html_utf8_to_utf16(pwriter->cd, ptr, len);
		ptr += len;
		if (w1 == 0)
			continue;
		else if (w2 == 0)
			snprintf(tmp_buff, sizeof(tmp_buff), "\\u%hu?", w1);
		else
			/* MSO uses %hd, which is a bad joke but expected */
			snprintf(tmp_buff, sizeof(tmp_buff), "\\uc0\\u%hu\\uc1\\u%hu?", w1, w2);

		tmp_len = strlen(tmp_buff);
		QRF(pwriter->ext_push.p_bytes(tmp_buff, tmp_len));
	}
	return ecSuccess;
}
 
/* writes RTF document header */
static ec_error_t html_write_header(RTF_WRITER*pwriter)
{
	int length;
	char tmp_string[256];
	size_t i = 0;
	
	static constexpr char head[] = "{\\rtf1\\ansi\\fbidis\\ansicpg1252\\deff0{\\fonttbl";
	QRF(pwriter->ext_push.p_bytes(head, strlen(head)));
	for (const auto &font : pwriter->fonts_ordered) {
		length = snprintf(tmp_string, std::size(tmp_string),
		         "{\\f%zu\\fswiss\\fcharset%d ", i++,
		         strcasecmp(font.c_str(), "symbol") == 0 ? 2 : 0);
		QRF(pwriter->ext_push.p_bytes(tmp_string, length));
		ERF(html_write_string(pwriter, font.c_str()));
		QRF(pwriter->ext_push.p_bytes(";}", 2));
	}
	QRF(pwriter->ext_push.p_bytes("}{\\colortbl", 11));
	for (auto color : pwriter->colors_ordered) {
		length = snprintf(tmp_string, std::size(tmp_string), "\\red%d\\green%d\\blue%d;",
		         (color >> 16) & 0xff, (color >> 8) & 0xff,
		         color & 0xFF);
		QRF(pwriter->ext_push.p_bytes(tmp_string, length));
	}
	static constexpr char foot[] =
		"}\n{\\*\\generator gromox-rtf;}"
		"\n{\\*\\formatConverter converted from html;}"
		"\\viewkind5\\viewscale100\n{\\*\\bkmkstart BM_BEGIN}";
	QRF(pwriter->ext_push.p_bytes(foot, strlen(foot)));
	return ecSuccess;
}

static ec_error_t html_write_close_brace(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_uint8('}'));
	return ecSuccess;
}

static ec_error_t html_write_style_color(RTF_WRITER *pwriter, int color)
{
	int index;
	int length;
	char tmp_buff[256];
	
	index = html_get_colortable(pwriter, color);
	if (index >= 0) {
		length = snprintf(tmp_buff, std::size(tmp_buff), "\\cf%d ", index);
		QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	}
	return ecSuccess;
}

static ec_error_t html_write_style_font_family(
	RTF_WRITER *pwriter, const char *font_name)
{
	int index;
	int length;
	char tmp_buff[256];
	
	index = html_get_fonttable(pwriter, font_name);
	if (index >= 0) {
		length = snprintf(tmp_buff, std::size(tmp_buff), "\\f%d ", index);
		QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	}
	return ecSuccess;
}

static ec_error_t html_write_style_font_size(RTF_WRITER *pwriter,
    int font_size, bool unit_point)
{
	int length;
	char tmp_buff[256];
	
	if (!unit_point)
		/* 1px = 0.75292857248934pt */
		font_size = (int)(((double)font_size)*0.75292857248934*2);
	else
		font_size *= 2;
	length = snprintf(tmp_buff, std::size(tmp_buff), "\\fs%d ", font_size);
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return ecSuccess;
}

static ec_error_t html_write_style_line_height(RTF_WRITER *pwriter, int line_height)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, std::size(tmp_buff), "\\sl%d ", line_height*15);
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return ecSuccess;
}

static ec_error_t html_write_style_margin_top(RTF_WRITER *pwriter, int margin_top)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, std::size(tmp_buff), "\\sa%d ", margin_top*15);
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return ecSuccess;
}

static ec_error_t html_write_style_text_indent(RTF_WRITER *pwriter, int text_indent)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, std::size(tmp_buff), "\\fi%d ", text_indent*15);
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return ecSuccess;
}

static void html_trim_style_value(char *value)
{
	char *ptr;
	int tmp_len;
	
	ptr = strchr(value, ',');
	if (NULL != ptr) {
		*ptr = '\0';
	}
	HX_strrtrim(value);
	tmp_len = strlen(value);
	if ('"' == value[0] || '\'' == value[0]) {
		memmove(value, value + 1, tmp_len);
		tmp_len --;
	}
	if ('"' == value[tmp_len - 1] ||
		'\'' == value[tmp_len - 1]) {
		value[tmp_len - 1] = '\0';
	}
}

static int html_convert_color(const char *value)
{
	int color;
	const char *ptr;
	const char *ptr1;
	char color_string[128], tmp_buff[8];
	
	if ('#' == value[0]) {
		if (!decode_hex_binary(value + 1, tmp_buff, 3))
			return -1;
		color = ((int)tmp_buff[0]) << 16 |
			((int)tmp_buff[1]) << 8 | tmp_buff[2];
		return color;
	}
	if (0 == strncasecmp(value, "rgb(", 4)) {
		ptr = value + 4;
		ptr1 = strchr(ptr, ',');
		if (ptr1 == nullptr || static_cast<size_t>(ptr1 - ptr) >= sizeof(tmp_buff))
			return -1;
		memcpy(tmp_buff, ptr, ptr1 - ptr);
		tmp_buff[ptr1 - ptr] = '\0';
		int tmp_val = strtol(tmp_buff, nullptr, 0);
		if (tmp_val < 0 || tmp_val > 255) {
			return -1;
		}
		color = tmp_val << 16;
		ptr = ptr1;
		ptr1 = strchr(ptr, ',');
		if (ptr1 == nullptr || static_cast<size_t>(ptr1 - ptr) >= sizeof(tmp_buff))
			return -1;
		memcpy(tmp_buff, ptr, ptr1 - ptr);
		tmp_buff[ptr1 - ptr] = '\0';
		tmp_val = strtol(tmp_buff, nullptr, 0);
		if (tmp_val < 0 || tmp_val > 255) {
			return -1;
		}
		color |= tmp_val << 8;
		ptr = ptr1;
		ptr1 = strchr(ptr, ')');
		if (ptr1 == nullptr || static_cast<size_t>(ptr1 - ptr) >= sizeof(tmp_buff))
			return -1;
		memcpy(tmp_buff, ptr, ptr1 - ptr);
		tmp_buff[ptr1 - ptr] = '\0';
		tmp_val = strtol(tmp_buff, nullptr, 0);
		if (tmp_val < 0 || tmp_val > 255) {
			return -1;
		}
		color |= tmp_val;
		return color;
	}
	gx_strlcpy(color_string, value, std::size(color_string));
	HX_strlower(color_string);
	auto it = std::lower_bound(std::begin(color_map), std::end(color_map), color_string,
	          [](const std::pair<const char *, rgb_t> &pair, const char *k) {
	          	return strcmp(pair.first, k) < 0;
	          });
	if (it == std::end(color_map) || strcmp(it->first, color_string) != 0)
		return -1;
	return it->second;
}

static bool html_match_style(const char *style_string,
	const char *tag, char *value, int val_len)
{
	int tmp_len;
	const char *ptr;
	const char *ptr1;
	
	ptr = strcasestr(style_string, tag);
	if (NULL == ptr) {
		return false;
	}
	ptr += strlen(tag);
	while (':' != *ptr) {
		if (' ' != *ptr && '\t' != *ptr) {
			return false;
		}
		ptr ++;
	}
	ptr ++;
	ptr1 = strchr(ptr, ';');
	if (NULL == ptr1) {
		ptr1 = style_string + strlen(style_string);
	}
	tmp_len = ptr1 - ptr;
	if (tmp_len > val_len - 1) {
		tmp_len = val_len - 1;
	}
	memcpy(value, ptr, tmp_len);
	value[tmp_len] = '\0';
	HX_strrtrim(value);
	HX_strltrim(value);
	return true;
}

static ec_error_t html_write_style(RTF_WRITER *pwriter, const xmlNode *pelement)
{
	int color;
	char value[128];
	
	auto pattribute = xml_getprop(pelement, "style");
	if (NULL == pattribute) {
		return ecSuccess;
	}
	if (html_match_style(pattribute,
		"font-family", value, sizeof(value))) {
		html_trim_style_value(value);
		ERF(html_write_style_font_family(pwriter, value));
	}
	if (html_match_style(pattribute,
		"font-size", value, sizeof(value))) {
		auto unit_point = strtailcase(value, "pt") == 0;
		ERF(html_write_style_font_size(pwriter, strtol(value, nullptr, 0), unit_point));
	}
	if (html_match_style(pattribute,
		"line-height", value, sizeof(value))) {
		if (strtailcase(value, "px") == 0)
			ERF(html_write_style_line_height(pwriter, strtol(value, nullptr, 0)));
	}
	if (html_match_style(pattribute,
		"margin-top", value, sizeof(value))) {
		if (strtailcase(value, "px") == 0)
			ERF(html_write_style_margin_top(pwriter, strtol(value, nullptr, 0)));
	}
	if (html_match_style(pattribute,
		"text-indent", value, sizeof(value))) {
		if (strtailcase(value, "px") == 0)
			ERF(html_write_style_text_indent(pwriter, strtol(value, nullptr, 0)));
	}
	if (html_match_style(pattribute,
		"color", value, sizeof(value))) {
		color = html_convert_color(value);
		if (color != -1) {
			ERF(html_write_style_color(pwriter, color));
		}
	}
	return ecSuccess;
}

static ec_error_t html_write_a_begin(RTF_WRITER *pwriter, const char *link)
{
	char tmp_buff[1024];
	auto length = gx_snprintf(tmp_buff, std::size(tmp_buff),
			"{\\field{\\*\\fldinst{HYPERLINK %s}}"
			"{\\fldrslt\\cf0 ", link);
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return ecSuccess;
}

static ec_error_t html_write_a_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_bytes("}}", 2));
	return ecSuccess;
}

static ec_error_t html_write_b_begin(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_bytes("{\\b ", 4));
	return ecSuccess;
}

static ec_error_t html_write_i_begin(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_bytes("{\\i ", 4));
	return ecSuccess;
}

static ec_error_t html_write_div_begin(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_bytes("{\\pard ", 7));
	return ecSuccess;
}

static ec_error_t html_write_div_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_bytes("\\sb70\\par}", 10));
	return ecSuccess;
}

static ec_error_t html_write_s_begin(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_bytes("{\\strike ", 9));
	return ecSuccess;
}

static ec_error_t html_write_ol_begin(RTF_WRITER *pwriter)
{
	static constexpr char x[] =
		"{{\\*\\pn\\pnlvlbody\\pnf0\\pnindent0\\pnstart1\\pndec"
		"{\\pntxta.}}\\fi-360\\li720\\sa200\\sl276\\slmult1 ";
	QRF(pwriter->ext_push.p_bytes(x, strlen(x)));
	return ecSuccess;
}

static ec_error_t html_write_ul_begin(RTF_WRITER *pwriter)
{
	static constexpr char x[] =
		"{{\\*\\pn\\pnlvlblt\\pnf1\\pnindent0{\\pntxtb\\"
		"\'B7}}\\fi-360\\li720\\sa200\\sl276\\slmult1 ";
	QRF(pwriter->ext_push.p_bytes(x, strlen(x)));
	return ecSuccess;
}

static ec_error_t html_write_li_begin(RTF_WRITER *pwriter)
{
	static constexpr char x[] = "{\\pntext\\tab\\f3 \\'b7}";
	QRF(pwriter->ext_push.p_bytes(x, strlen(x)));
	return ecSuccess;
}

static ec_error_t html_write_li_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_bytes("\\par\n", 5));
	return ecSuccess;
}

static ec_error_t html_write_center_begin(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_bytes("{\\pard\\qr ", 10));
	return ecSuccess;
}

static ec_error_t html_write_center_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_bytes("\\par}", 5));
	return ecSuccess;
}

static ec_error_t html_write_span_begin(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_uint8('{'));
	return ecSuccess;
}

#define html_write_tail html_write_close_brace
#define html_write_b_end html_write_close_brace
#define html_write_i_end html_write_close_brace
#define html_write_s_end html_write_close_brace
#define html_write_ol_end html_write_close_brace
#define html_write_ul_end html_write_close_brace
#define html_write_h_begin html_write_div_begin
#define html_write_h_end html_write_div_end
#define html_write_p_begin html_write_div_begin
#define html_write_p_end html_write_div_end
#define html_write_em_begin html_write_b_begin
#define html_write_em_end html_write_b_end
#define html_write_table_begin html_write_span_begin
#define html_write_table_end html_write_span_end
#define html_write_font_begin html_write_span_begin
#define html_write_font_end html_write_span_end
#define html_write_span_end html_write_close_brace
#define html_write_mark_end html_write_close_brace
#define html_write_sub_end html_write_close_brace
#define html_write_sup_end html_write_close_brace

static ec_error_t html_write_mark_begin(RTF_WRITER *pwriter)
{
	int index;
	int length;
	char tmp_buff[256];
	
	QRF(pwriter->ext_push.p_uint8('{'));
	index = html_get_colortable(pwriter, 0xFFFF00);
	if (index >= 0) {
		length = snprintf(tmp_buff, std::size(tmp_buff), "\\highlight%d ", index);
		QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	}
	return ecSuccess;
}

static ec_error_t html_write_td_begin(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_bytes("{\\pard\\intbl\\qc ", 16));
	return ecSuccess;
}

static ec_error_t html_write_td_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_bytes("\\cell}\n", 7));
	return ecSuccess;
}

static ec_error_t html_write_th_begin(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_bytes("{\\pard\\intbl\\qc ", 16));
	return ecSuccess;
}

static ec_error_t html_write_th_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_bytes("\\cell}\n", 7));
	return ecSuccess;
}

static ec_error_t html_write_tr_begin(RTF_WRITER *pwriter, int cell_num)
{
	int i;
	int length;
	char tmp_buff[256];
	
	QRF(pwriter->ext_push.p_bytes("{\\trowd\\trgaph10 ", 16));
	if (0 == cell_num) {
		return ecSuccess;
	}
	auto percell = 8503.0 / cell_num;
	for (i=0; i<cell_num; i++) {
		length = snprintf(tmp_buff, std::size(tmp_buff), "\\clbrdrt\\brdrw15\\brdrs"
				"\\clbrdrl\\brdrw15\\brdrs\\clbrdrb\\brdrw15"
				"\\brdrs\\clbrdrr\\brdrw15\\brdrs\\cellx%d\n",
				(int)(percell*(i + 1)));
		QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	}
	return ecSuccess;
}

static ec_error_t html_write_tr_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_bytes("\\row}\n", 6));
	return ecSuccess;
}

static ec_error_t html_write_sub_begin(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_bytes("{\\sub ", 6));
	return ecSuccess;
}

static ec_error_t html_write_sup_begin(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_bytes("{\\super ", 8));
	return ecSuccess;
}

static ec_error_t html_write_br(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_bytes("\\line ", 6));
	return ecSuccess;
}

static ec_error_t html_write_hr(RTF_WRITER *pwriter)
{
	static constexpr char x[] =
			"\\pard\\brdrb\\brdrs"
			"\\brdrw10\\brsp20{\\fs4\\~}\\par\\pard ";
	QRF(pwriter->ext_push.p_bytes(x, strlen(x)));
	return ecSuccess;
}

static ec_error_t html_write_children(RTF_WRITER *pwriter, const xmlNode *pnode)
{
	ERF(html_write_style(pwriter, pnode));
	for (pnode = pnode->children; pnode != nullptr; pnode = pnode->next) {
		ERF(html_enum_write(pwriter, pnode));
	}
	return ecSuccess;
}

static htag lookup_tag(const xmlNode *nd)
{
	auto k = signed_cast<const char *>(nd->name);
	auto it = std::lower_bound(std::begin(htmltags), std::end(htmltags), k,
	          [](const struct tagentry &x, const char *s) { return strcasecmp(x.name, s) < 0; });
	return it != std::end(htmltags) && strcasecmp(it->name, k) == 0 ?
	       it->tag : htag::none;
}

static bool html_check_parent_type(const xmlNode *pnode, htag tag)
{
	while (NULL != pnode->parent) {
		pnode = pnode->parent;
		if (pnode->type == XML_ELEMENT_NODE && lookup_tag(pnode) == tag)
			return true;
	}
	return false;
}

static ec_error_t html_enum_write(RTF_WRITER *pwriter, const xmlNode *pnode)
{
	int color;
	int cell_num;
	
	if (pnode->type == XML_ELEMENT_NODE) {
		switch (lookup_tag(pnode)) {
		case htag::a: {
			auto pvalue = znul(xml_getprop(pnode, "href"));
			ERF(html_write_a_begin(pwriter, pvalue));
			ERF(html_write_children(pwriter, pnode));
			return html_write_a_end(pwriter);
		}
		case htag::b:
			ERF(html_write_b_begin(pwriter));
			ERF(html_write_children(pwriter, pnode));
			return html_write_b_end(pwriter);
		case htag::i:
			ERF(html_write_i_begin(pwriter));
			ERF(html_write_children(pwriter, pnode));
			return html_write_i_end(pwriter);
		case htag::div:
			ERF(html_write_div_begin(pwriter));
			ERF(html_write_children(pwriter, pnode));
			return html_write_div_end(pwriter);
		case htag::h1:
		case htag::h2:
		case htag::h3:
		case htag::h4:
		case htag::h5:
		case htag::h6:
			ERF(html_write_h_begin(pwriter));
			ERF(html_write_children(pwriter, pnode));
			return html_write_h_end(pwriter);
		case htag::p:
			ERF(html_write_p_begin(pwriter));
			ERF(html_write_children(pwriter, pnode));
			return html_write_p_end(pwriter);
		case htag::s:
			ERF(html_write_s_begin(pwriter));
			ERF(html_write_children(pwriter, pnode));
			return html_write_s_end(pwriter);
		case htag::br:
			return html_write_br(pwriter);
		case htag::hr:
			return html_write_hr(pwriter);
		case htag::em:
			ERF(html_write_em_begin(pwriter));
			ERF(html_write_children(pwriter, pnode));
			return html_write_em_end(pwriter);
		case htag::ol:
			ERF(html_write_ol_begin(pwriter));
			ERF(html_write_children(pwriter, pnode));
			return html_write_ol_end(pwriter);
		case htag::ul:
			ERF(html_write_ul_begin(pwriter));
			ERF(html_write_children(pwriter, pnode));
			return html_write_ul_end(pwriter);
		case htag::li:
			ERF(html_write_li_begin(pwriter));
			ERF(html_write_children(pwriter, pnode));
			return html_write_li_end(pwriter);
		case htag::center:
			ERF(html_write_center_begin(pwriter));
			ERF(html_write_children(pwriter, pnode));
			return html_write_center_end(pwriter);
		case htag::table:
			if (html_check_parent_type(pnode, htag::table))
				return ecSuccess;
			ERF(html_write_table_begin(pwriter));
			ERF(html_write_children(pwriter, pnode));
			return html_write_table_end(pwriter);
		case htag::span:
			ERF(html_write_span_begin(pwriter));
			ERF(html_write_children(pwriter, pnode));
			return html_write_span_end(pwriter);
		case htag::font: {
			ERF(html_write_font_begin(pwriter));
			auto pattribute = xml_getprop(pnode, "face");
			if (pattribute != nullptr)
				ERF(html_write_style_font_family(pwriter, pattribute));
			pattribute = xml_getprop(pnode, "color");
			if (NULL != pattribute) {
				color = html_convert_color(pattribute);
				if (color != -1)
					ERF(html_write_style_color(pwriter, color));
			}
			pattribute = xml_getprop(pnode, "size");
			if (pattribute != nullptr)
				ERF(html_write_style_font_size(pwriter,
					strtol(pattribute, nullptr, 0) * 3 + 8, false));
			ERF(html_write_children(pwriter, pnode));
			return html_write_font_end(pwriter);
		}
		case htag::mark:
			ERF(html_write_mark_begin(pwriter));
			ERF(html_write_children(pwriter, pnode));
			return html_write_mark_end(pwriter);
		case htag::td:
			ERF(html_write_td_begin(pwriter));
			ERF(html_write_children(pwriter, pnode));
			return html_write_td_end(pwriter);
		case htag::th:
			ERF(html_write_th_begin(pwriter));
			ERF(html_write_children(pwriter, pnode));
			return html_write_th_end(pwriter);
		case htag::tr:
			cell_num = 0;
			for (auto ptr = pnode->children; ptr != nullptr; ptr = ptr->next)
				if (ptr->type == XML_ELEMENT_NODE)
					cell_num ++;
			ERF(html_write_tr_begin(pwriter, cell_num));
			ERF(html_write_children(pwriter, pnode));
			return html_write_tr_end(pwriter);
		case htag::sub:
			ERF(html_write_sub_begin(pwriter));
			ERF(html_write_children(pwriter, pnode));
			return html_write_sub_end(pwriter);
		case htag::sup:
			ERF(html_write_sup_begin(pwriter));
			ERF(html_write_children(pwriter, pnode));
			return html_write_sup_end(pwriter);
		default:
			return html_write_children(pwriter, pnode);
		}
	} else if (pnode->type == XML_TEXT_NODE) {
		if (!html_check_parent_type(pnode, htag::style) &&
		    !html_check_parent_type(pnode, htag::script))
			return html_write_string(pwriter, signed_cast<const char *>(pnode->content));
	}
	return ecSuccess;
}

static void html_enum_tables(RTF_WRITER *pwriter, xmlNode *pnode)
{
	int color;
	char value[128];
	
	if (pnode->type != XML_ELEMENT_NODE)
		return;
	if (lookup_tag(pnode) == htag::font) {
		auto pattribute = xml_getprop(pnode, "face");
		if (NULL != pattribute) {
			html_set_fonttable(pwriter, pattribute);
		}
		pattribute = xml_getprop(pnode, "color");
		if (NULL != pattribute) {
			color = html_convert_color(pattribute);
			if (-1 != color) {
				html_set_colortable(pwriter, color);
			}
		}
	}
	auto pattribute = xml_getprop(pnode, "style");
	if (NULL != pattribute) {
		if (html_match_style(pattribute,
			"font-family", value, sizeof(value))) {
			html_trim_style_value(value);
			html_set_fonttable(pwriter, value);
		}
		if (html_match_style(pattribute,
			"color", value, sizeof(value))) {
			color = html_convert_color(value);
			if (-1 != color) {
				html_set_colortable(pwriter, color);
			}
		}
	}
	for (pnode = pnode->children; pnode != nullptr; pnode = pnode->next)
		html_enum_tables(pwriter, pnode);
}

ec_error_t html_to_rtf(const void *pbuff_in, size_t length, cpid_t cpid,
    char **pbuff_out, size_t *plength) try
{
	RTF_WRITER writer;

	std::unique_ptr<char[]> buff_inz(new(std::nothrow) char[length+1]);
	if (buff_inz == nullptr)
		return ecMAPIOOM;
	memcpy(buff_inz.get(), pbuff_in, length);
	buff_inz[length] = '\0';

	*pbuff_out = nullptr;
	cpid_cstr_compatible(cpid);
	auto cset = cpid_to_cset(cpid);
	if (cset == nullptr)
		cset = "windows-1252";
	cset = replace_iconv_charset(cset);
	auto buffer = iconvtext(static_cast<const char *>(pbuff_in),
	              length, cset, "UTF-8");
	auto ret = html_init_writer(&writer);
	if (ret != ecSuccess)
		return ret;
	auto hdoc = htmlReadMemory(buffer.c_str(), buffer.size(), nullptr, "utf-8",
	            HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING | HTML_PARSE_NONET);
	if (hdoc == nullptr)
		return ecError;
	auto root = xmlDocGetRootElement(hdoc);
	if (root != nullptr) {
		html_enum_tables(&writer, root);
		ERF(html_write_header(&writer));
		ERF(html_enum_write(&writer, root));
		ERF(html_write_tail(&writer));
	}
	*plength = writer.ext_push.m_offset;
	*pbuff_out = me_alloc<char>(*plength);
	if (*pbuff_out != nullptr)
		memcpy(*pbuff_out, writer.ext_push.m_udata, *plength);
	xmlFreeDoc(hdoc);
	return *pbuff_out != nullptr ? ecSuccess : ecMAPIOOM;
} catch (const std::bad_alloc &) {
	return ecMAPIOOM;
}
