// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cassert>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gumbo.h>
#include <iconv.h>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/double_list.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/html.hpp>
#include <gromox/int_hash.hpp>
#include <gromox/str_hash.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#define QRF(expr) do { int klfdv = (expr); if (klfdv != EXT_ERR_SUCCESS) return false; } while (false)
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
	EXT_PUSH ext_push{};
	std::map<std::string, unsigned int> pfont_hash /* font -> index */;
	std::map<rgb_t, unsigned int> pcolor_hash; /* color -> index */
	std::vector<rgb_t> colors_ordered; /* index -> color */
	std::vector<std::string> fonts_ordered; /* index -> font */
};
}

static iconv_t g_conv_id;
static std::map<std::string, rgb_t> g_color_hash;

static BOOL html_enum_write(RTF_WRITER *pwriter, GumboNode *pnode);

BOOL html_init_library()
{
	static constexpr std::pair<const char *, rgb_t> color_map[] =
		{{"black",				0x000000},
		{"silver",				0xc0c0c0},
		{"gray",				0x808080},
		{"white",				0xffffff},
		{"maroon",				0x800000},
		{"red",					0xff0000},
		{"purple",				0x800080},
		{"fuchsia",				0xff00ff},
		{"green",				0x008000},
		{"lime",				0x00ff00},
		{"olive",				0x808000},
		{"yellow",				0xffff00},
		{"navy",				0x000080},
		{"blue",				0x0000ff},
		{"teal",				0x008080},
		{"aqua",				0x00ffff},
		{"orange",				0xffa500},
		{"aliceblue",			0xf0f8ff},
		{"antiquewhite",		0xfaebd7},
		{"aquamarine",			0x7fffd4},
		{"azure",				0xf0ffff},
		{"beige",				0xf5f5dc},
		{"bisque",				0xffe4c4},
		{"blanchedalmond",		0xffebcd},
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
		{"gainsboro",			0xdcdcdc},
		{"ghostwhite",			0xf8f8ff},
		{"gold",				0xffd700},
		{"goldenrod",			0xdaa520},
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
		{"limegreen",			0x32cd32},
		{"linen",				0xfaf0e6},
		{"magenta",				0xff00ff},
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
		{"oldlace",				0xfdf5e6},
		{"olivedrab",			0x6b8e23},
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
		{"rosybrown",			0xbc8f8f},
		{"royalblue",			0x4169e1},
		{"saddlebrown",			0x8b4513},
		{"salmon",				0xfa8072},
		{"sandybrown",			0xf4a460},
		{"seagreen",			0x2e8b57},
		{"seashell",			0xfff5ee},
		{"sienna",				0xa0522d},
		{"skyblue",				0x87ceeb},
		{"slateblue",			0x6a5acd},
		{"slategray",			0x708090},
		{"slategrey",			0x708090},
		{"snow",				0xfffafa},
		{"springgreen",			0x00ff7f},
		{"steelblue",			0x4682b4},
		{"tan",					0xd2b48c},
		{"thistle",				0xd8bfd8},
		{"tomato",				0xff6347},
		{"turquoise",			0x40e0d0},
		{"violet",				0xee82ee},
		{"wheat",				0xf5deb3},
		{"whitesmoke",			0xf5f5f5},
		{"yellowgreen",			0x9acd32},
		{"rebeccapurple",		0x663399}};

	textmaps_init();
	if (g_color_hash.size() > 0)
		return TRUE;
	try {
		for (const auto &e : color_map)
			g_color_hash.emplace(e.first, e.second);
	} catch (const std::bad_alloc &) {
		g_color_hash.clear();
		return FALSE;
	}
	g_conv_id = iconv_open("UTF-16LE", "UTF-8");
	if ((iconv_t)-1 == g_conv_id) {
		return FALSE;
	}
	return TRUE;
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

static BOOL html_init_writer(RTF_WRITER *pwriter) 
{
	if (!pwriter->ext_push.init(nullptr, 0, 0))
		return FALSE;	
	html_set_fonttable(pwriter, "Times New Roman");
	html_set_fonttable(pwriter, "Arial");
	/* first item in font table is for symbol */
	html_set_fonttable(pwriter, "symbol");
	/* first item in color table is for anchor link */
	html_set_colortable(pwriter, 0x0645AD);
	return TRUE;
} 
 
static int html_utf8_byte_num(unsigned char ch)
{
	int byte_num = 0;

	if (ch >= 0xFC && ch < 0xFE) {
		byte_num = 6;
	} else if (ch >= 0xF8) {
		byte_num = 5;
	} else if (ch >= 0xF0) {
		byte_num = 4;
	} else if (ch >= 0xE0) {
		byte_num = 3;
	} else if (ch >= 0xC0) {
		byte_num = 2;
	} else if (0 == (ch & 0x80)) {
		byte_num = 1;
	}
	return byte_num;
}

static uint32_t html_utf8_to_wchar(const char *src, int length)
{
	size_t len;
	size_t in_len;
	uint32_t wchar;
	
	auto pin = deconst(src);
	auto pout = reinterpret_cast<char *>(&wchar);
	in_len = length;
	len = sizeof(uint16_t);
	return iconv(g_conv_id, &pin, &in_len, &pout, &len) == static_cast<size_t>(-1) ||
	       len != 0 ? 0 : wchar;
}

static BOOL html_write_string(RTF_WRITER *pwriter, const char *string)
{
	int len;
	int tmp_len;
	uint16_t wchar;
	char tmp_buff[9];
	const char *ptr = string, *pend = string + strlen(string);

	while ('\0' != *ptr) {
		len = html_utf8_byte_num(*ptr);
		if (ptr + len > pend) {
			return FALSE;
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
		} else {
			wchar = html_utf8_to_wchar(ptr, len);
			if (0 == wchar) {
				return FALSE;
			}
			snprintf(tmp_buff, sizeof(tmp_buff), "\\u%hu?", wchar);
			tmp_len = strlen(tmp_buff);
			QRF(pwriter->ext_push.p_bytes(tmp_buff, tmp_len));
		}
		ptr += len;
	}
	return TRUE;
}
 
/* writes RTF document header */
static BOOL html_write_header(RTF_WRITER*pwriter)
{
	int length;
	char tmp_string[256];
	size_t i = 0;
	
	length = sprintf(tmp_string,
		"{\\rtf1\\ansi\\fbidis\\ansicpg1252\\deff0");
	QRF(pwriter->ext_push.p_bytes(tmp_string, length));
	QRF(pwriter->ext_push.p_bytes("{\\fonttbl", 9));
	for (const auto &font : pwriter->fonts_ordered) {
		length = snprintf(tmp_string, GX_ARRAY_SIZE(tmp_string),
		         "{\\f%zu\\fswiss\\fcharset%d ", i++,
		         strcasecmp(font.c_str(), "symbol") == 0 ? 2 : 0);
		QRF(pwriter->ext_push.p_bytes(tmp_string, length));
		if (!html_write_string(pwriter, font.c_str()))
			return FALSE;
		QRF(pwriter->ext_push.p_bytes(";}", 2));
	}
	QRF(pwriter->ext_push.p_bytes("}{\\colortbl", 11));
	for (auto color : pwriter->colors_ordered) {
		length = snprintf(tmp_string, arsizeof(tmp_string), "\\red%d\\green%d\\blue%d;",
		         (color >> 16) & 0xff, (color >> 8) & 0xff,
		         color & 0xFF);
		QRF(pwriter->ext_push.p_bytes(tmp_string, length));
	}
	length = sprintf(tmp_string,
		"}\n{\\*\\generator gromox-rtf;}"
		"\n{\\*\\formatConverter converted from html;}"
		"\\viewkind5\\viewscale100\n{\\*\\bkmkstart BM_BEGIN}");
	QRF(pwriter->ext_push.p_bytes(tmp_string, length));
	return TRUE;
}

static BOOL html_write_tail(RTF_WRITER*pwriter)
{
	QRF(pwriter->ext_push.p_uint8('}'));
	return TRUE;
}

static BOOL html_write_style_color(RTF_WRITER *pwriter, int color)
{
	int index;
	int length;
	char tmp_buff[256];
	
	index = html_get_colortable(pwriter, color);
	if (index >= 0) {
		length = snprintf(tmp_buff, arsizeof(tmp_buff), "\\cf%d", index);
		QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	}
	return TRUE;
}

static BOOL html_write_style_font_family(
	RTF_WRITER *pwriter, const char *font_name)
{
	int index;
	int length;
	char tmp_buff[256];
	
	index = html_get_fonttable(pwriter, font_name);
	if (index >= 0) {
		length = snprintf(tmp_buff, arsizeof(tmp_buff), "\\f%d ", index);
		QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	}
	return TRUE;
}

static BOOL html_write_style_font_size(RTF_WRITER *pwriter,
	int font_size, BOOL unit_point)
{
	int length;
	char tmp_buff[256];
	
	if (!unit_point)
		/* 1px = 0.75292857248934pt */
		font_size = (int)(((double)font_size)*0.75292857248934*2);
	else
		font_size *= 2;
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "\\fs%d ", font_size);
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_style_line_height(RTF_WRITER *pwriter, int line_height)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "\\sl%d ", line_height*15);
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_style_margin_top(RTF_WRITER *pwriter, int margin_top)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "\\sa%d ", margin_top*15);
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_style_text_indent(RTF_WRITER *pwriter, int text_indent)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "\\fi%d ", text_indent*15);
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
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
	gx_strlcpy(color_string, value, GX_ARRAY_SIZE(color_string));
	HX_strlower(color_string);
	auto it = g_color_hash.find(color_string);
	return it != g_color_hash.cend() ? it->second : -1;
}

static BOOL html_match_style(const char *style_string,
	const char *tag, char *value, int val_len)
{
	int tmp_len;
	const char *ptr;
	const char *ptr1;
	
	ptr = strcasestr(style_string, tag);
	if (NULL == ptr) {
		return FALSE;
	}
	ptr += strlen(tag);
	while (':' != *ptr) {
		if (' ' != *ptr && '\t' != *ptr) {
			return FALSE;
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
	return TRUE;
}

static BOOL html_write_style(RTF_WRITER *pwriter, GumboElement *pelement)
{
	int color;
	int value_len;
	char value[128];
	BOOL unit_point;
	GumboAttribute *pattribute;
	
	pattribute = gumbo_get_attribute(&pelement->attributes, "style");
	if (NULL == pattribute) {
		return TRUE;
	}
	if (html_match_style(pattribute->value,
		"font-family", value, sizeof(value))) {
		html_trim_style_value(value);
		if (!html_write_style_font_family(pwriter, value))
			return FALSE;
	}
	if (html_match_style(pattribute->value,
		"font-size", value, sizeof(value))) {
		value_len = strlen(value);
		if (0 == strcasecmp(value + value_len - 2, "pt")) {
			unit_point = TRUE;
		} else {
			unit_point = FALSE;
		}
		if (!html_write_style_font_size(pwriter,
		    strtol(value, nullptr, 0), unit_point))
			return FALSE;	
	}
	if (html_match_style(pattribute->value,
		"line-height", value, sizeof(value))) {
		value_len = strlen(value);
		if (0 == strcasecmp(value + value_len - 2, "px")) {
			if (!html_write_style_line_height(pwriter,
			    strtol(value, nullptr, 0)))
				return FALSE;	
		}
	}
	if (html_match_style(pattribute->value,
		"margin-top", value, sizeof(value))) {
		value_len = strlen(value);
		if (0 == strcasecmp(value + value_len - 2, "px")) {
			if (!html_write_style_margin_top(pwriter,
			    strtol(value, nullptr, 0)))
				return FALSE;	
		}
	}
	if (html_match_style(pattribute->value,
		"text-indent", value, sizeof(value))) {
		value_len = strlen(value);
		if (strcasecmp(value + value_len - 2, "px") == 0 &&
		    !html_write_style_text_indent(pwriter,
		    strtol(value, nullptr, 0)))
			return FALSE;
	}
	if (html_match_style(pattribute->value,
		"color", value, sizeof(value))) {
		color = html_convert_color(value);
		if (color != -1 && !html_write_style_color(pwriter, color))
			return FALSE;
	}
	return TRUE;
}

static BOOL html_write_a_begin(RTF_WRITER *pwriter, const char *link)
{
	char tmp_buff[1024];
	int length = gx_snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff),
			"{\\field{\\*\\fldinst{HYPERLINK %s}}"
			"{\\fldrslt\\cf0 ", link);
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_a_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_bytes("}}", 2));
	return TRUE;
}

static BOOL html_write_b_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "{\\b ");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_b_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_uint8('}'));
	return TRUE;
}

static BOOL html_write_i_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "{\\i ");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_i_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_uint8('}'));
	return TRUE;
}

static BOOL html_write_div_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "{\\pard ");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_div_end(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "\\sb70\\par}");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_h_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "{\\pard ");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_h_end(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "\\sb70\\par}");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_p_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "{\\pard ");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_p_end(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "\\sb70\\par}");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_s_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "{\\strike ");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_s_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_uint8('}'));
	return TRUE;
}

static BOOL html_write_em_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "{\\b ");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_em_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_uint8('}'));
	return TRUE;
}

static BOOL html_write_ol_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff,
		"{{\\*\\pn\\pnlvlbody\\pnf0\\pnindent0\\pnstart1\\pndec"
		"{\\pntxta.}}\\fi-360\\li720\\sa200\\sl276\\slmult1 ");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_ol_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_uint8('}'));
	return TRUE;
}

static BOOL html_write_ul_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff,
		"{{\\*\\pn\\pnlvlblt\\pnf1\\pnindent0{\\pntxtb\\"
		"\'B7}}\\fi-360\\li720\\sa200\\sl276\\slmult1 ");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_ul_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_uint8('}'));
	return TRUE;
}

static BOOL html_write_li_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "{\\pntext\\tab\\f3 \\'b7}");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_li_end(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "\\par\n");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_center_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "{\\pard\\qr ");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_center_end(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "\\par}");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_table_begin(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_uint8('{'));
	return TRUE;
}

static BOOL html_write_table_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_uint8('}'));
	return TRUE;
}

static BOOL html_write_span_begin(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_uint8('{'));
	return TRUE;
}

static BOOL html_write_span_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_uint8('}'));
	return TRUE;
}

static BOOL html_write_font_begin(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_uint8('{'));
	return TRUE;
}

static BOOL html_write_font_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_uint8('}'));
	return TRUE;
}

static BOOL html_write_mark_begin(RTF_WRITER *pwriter)
{
	int index;
	int length;
	char tmp_buff[256];
	
	QRF(pwriter->ext_push.p_uint8('{'));
	index = html_get_colortable(pwriter, 0xFFFF00);
	if (index >= 0) {
		length = snprintf(tmp_buff, arsizeof(tmp_buff), "\\highlight%d ", index);
		QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	}
	return TRUE;
}

static BOOL html_write_mark_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_uint8('}'));
	return TRUE;
}

static BOOL html_write_td_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "{\\pard\\intbl\\qc ");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_td_end(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "\\cell}\n");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_th_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "{\\pard\\intbl\\qc ");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_th_end(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "\\cell}\n");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_tr_begin(RTF_WRITER *pwriter, int cell_num)
{
	int i;
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "{\\trowd\\trgaph10 ");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	if (0 == cell_num) {
		return TRUE;
	}
	auto percell = 8503.0 / cell_num;
	for (i=0; i<cell_num; i++) {
		length = snprintf(tmp_buff, arsizeof(tmp_buff), "\\clbrdrt\\brdrw15\\brdrs"
				"\\clbrdrl\\brdrw15\\brdrs\\clbrdrb\\brdrw15"
				"\\brdrs\\clbrdrr\\brdrw15\\brdrs\\cellx%d\n",
				(int)(percell*(i + 1)));
		QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	}
	return TRUE;
}

static BOOL html_write_tr_end(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "\\row}\n");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_sub_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "{\\sub ");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_sub_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_uint8('}'));
	return TRUE;
}


static BOOL html_write_sup_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "{\\super ");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_sup_end(RTF_WRITER *pwriter)
{
	QRF(pwriter->ext_push.p_uint8('}'));
	return TRUE;
}

static BOOL html_write_br(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "\\line ");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_hr(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = snprintf(tmp_buff, arsizeof(tmp_buff), "\\pard\\brdrb\\brdrs"
			"\\brdrw10\\brsp20{\\fs4\\~}\\par\\pard ");
	QRF(pwriter->ext_push.p_bytes(tmp_buff, length));
	return TRUE;
}

static BOOL html_write_children(RTF_WRITER *pwriter, GumboNode *pnode)
{
	unsigned int i;
	
	if (!html_write_style(pwriter, &pnode->v.element))
		return FALSE;
	for (i = 0; i < pnode->v.element.children.length; ++i)
		if (!html_enum_write(pwriter,
		    static_cast<GumboNode *>(pnode->v.element.children.data[i])))
			return FALSE;
	return TRUE;
}

static BOOL html_check_parent_type(GumboNode *pnode, GumboTag tag)
{
	while (NULL != pnode->parent) {
		pnode = pnode->parent;
		if (GUMBO_NODE_ELEMENT == pnode->type
			&& pnode->v.element.tag == tag) {
			return TRUE;	
		}
	}
	return FALSE;
}

static BOOL html_enum_write(RTF_WRITER *pwriter, GumboNode *pnode)
{
	int color;
	int cell_num;
	unsigned int i;
	const char *pvalue;
	GumboAttribute *pattribute;
	
	if (GUMBO_NODE_ELEMENT == pnode->type) {
		switch (pnode->v.element.tag) {
		case GUMBO_TAG_A:
			pattribute = gumbo_get_attribute(
				&pnode->v.element.attributes, "href");
			pvalue = pattribute != nullptr ? pattribute->value : "";
			if (!html_write_a_begin(pwriter, pvalue) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_a_end(pwriter);
		case GUMBO_TAG_B:
			if (!html_write_b_begin(pwriter) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_b_end(pwriter);
		case GUMBO_TAG_I:
			if (!html_write_i_begin(pwriter) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_i_end(pwriter);
		case GUMBO_TAG_DIV:
			if (!html_write_div_begin(pwriter) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_div_end(pwriter);
		case GUMBO_TAG_H1:
		case GUMBO_TAG_H2:
		case GUMBO_TAG_H3:
		case GUMBO_TAG_H4:
		case GUMBO_TAG_H5:
		case GUMBO_TAG_H6:
			if (!html_write_h_begin(pwriter) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_h_end(pwriter);
		case GUMBO_TAG_P:
			if (!html_write_p_begin(pwriter) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_p_end(pwriter);
		case GUMBO_TAG_S:
			if (!html_write_s_begin(pwriter) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_s_end(pwriter);
		case GUMBO_TAG_BR:
			return html_write_br(pwriter);
		case GUMBO_TAG_HR:
			return html_write_hr(pwriter);
		case GUMBO_TAG_EM:
			if (!html_write_em_begin(pwriter) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_em_end(pwriter);
		case GUMBO_TAG_OL:
			if (!html_write_ol_begin(pwriter) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_ol_end(pwriter);
		case GUMBO_TAG_UL:
			if (!html_write_ul_begin(pwriter) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_ul_end(pwriter);
		case GUMBO_TAG_LI:
			if (!html_write_li_begin(pwriter) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_li_end(pwriter);
		case GUMBO_TAG_CENTER:
			if (!html_write_center_begin(pwriter) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_center_end(pwriter);
		case GUMBO_TAG_TABLE:
			if (html_check_parent_type(pnode, GUMBO_TAG_TABLE))
				return TRUE;
			if (!html_write_table_begin(pwriter) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_table_end(pwriter);
		case GUMBO_TAG_SPAN:
			if (!html_write_span_begin(pwriter) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_span_end(pwriter);
		case GUMBO_TAG_FONT:
			if (!html_write_font_begin(pwriter))
				return FALSE;
			pattribute = gumbo_get_attribute(
				&pnode->v.element.attributes, "face");
			if (pattribute != nullptr &&
			    !html_write_style_font_family(pwriter, pattribute->value))
				return FALSE;
			pattribute = gumbo_get_attribute(
				&pnode->v.element.attributes, "color");
			if (NULL != pattribute) {
				color = html_convert_color(pattribute->value);
				if (color != -1 &&
				    !html_write_style_color(pwriter, color))
					return FALSE;
			}
			pattribute = gumbo_get_attribute(
				&pnode->v.element.attributes, "size");
			if (pattribute != nullptr &&
			    !html_write_style_font_size(pwriter,
			    strtol(pattribute->value, nullptr, 0) * 3 + 8, false))
				return FALSE;
			if (!html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_font_end(pwriter);
		case GUMBO_TAG_MARK:
			if (!html_write_mark_begin(pwriter) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_mark_end(pwriter);
		case GUMBO_TAG_TD:
			if (!html_write_td_begin(pwriter) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_td_end(pwriter);
		case GUMBO_TAG_TH:
			if (!html_write_th_begin(pwriter) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_th_end(pwriter);
		case GUMBO_TAG_TR:
			cell_num = 0;
			for (i=0; i<pnode->v.element.children.length; i++) {
				if (GUMBO_NODE_ELEMENT == ((GumboNode*)
					pnode->v.element.children.data[i])->type) {
					cell_num ++;
				}
			}
			if (!html_write_tr_begin(pwriter, cell_num) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_tr_end(pwriter);
		case GUMBO_TAG_SUB:
			if (!html_write_sub_begin(pwriter) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_sub_end(pwriter);
		case GUMBO_TAG_SUP:
			if (!html_write_sup_begin(pwriter) ||
			    !html_write_children(pwriter, pnode))
				return FALSE;
			return html_write_sup_end(pwriter);
		default:
			return html_write_children(pwriter, pnode);
		}
	} else if (GUMBO_NODE_TEXT == pnode->type) {
		if (!html_check_parent_type(pnode, GUMBO_TAG_STYLE) &&
		    !html_check_parent_type(pnode, GUMBO_TAG_SCRIPT))
			return html_write_string(pwriter, pnode->v.text.text);
	}
	return TRUE;
}

static void html_enum_tables(RTF_WRITER *pwriter, GumboNode *pnode)
{
	int color;
	unsigned int i;
	char value[128];
	GumboAttribute *pattribute;
	
	if (GUMBO_NODE_ELEMENT != pnode->type) {
		return;
	}
	if (pnode->v.element.tag == GUMBO_TAG_FONT) {
		pattribute = gumbo_get_attribute(
			&pnode->v.element.attributes, "face");
		if (NULL != pattribute) {
			html_set_fonttable(pwriter, pattribute->value);
		}
		pattribute = gumbo_get_attribute(
			&pnode->v.element.attributes, "color");
		if (NULL != pattribute) {
			color = html_convert_color(znul(pattribute->value));
			if (-1 != color) {
				html_set_colortable(pwriter, color);
			}
		}
	}
	pattribute = gumbo_get_attribute(
		&pnode->v.element.attributes, "style");
	if (NULL != pattribute) {
		if (html_match_style(pattribute->value,
			"font-family", value, sizeof(value))) {
			html_trim_style_value(value);
			html_set_fonttable(pwriter, value);
		}
		if (html_match_style(pattribute->value,
			"color", value, sizeof(value))) {
			color = html_convert_color(value);
			if (-1 != color) {
				html_set_colortable(pwriter, color);
			}
		}
	}
	for (i=0; i<pnode->v.element.children.length; i++) {
		html_enum_tables(pwriter,
			static_cast<GumboNode *>(pnode->v.element.children.data[i]));
	}
}

static void html_string_to_utf8(uint32_t cpid,
	const char *src, char *dst, size_t len)
{
	size_t in_len;
	iconv_t conv_id;
	
	auto charset = cpid_to_cset(cpid);
	if (NULL == charset) {
		charset = "windows-1252";
	}
	conv_id = iconv_open("UTF-8//IGNORE",
		replace_iconv_charset(charset));
	auto pin = deconst(src);
	auto pout = dst;
	in_len = strlen(src);
	memset(dst, 0, len);
	iconv(conv_id, &pin, &in_len, &pout, &len);	
	*pout = '\0';
	iconv_close(conv_id);
}

BOOL html_to_rtf(const void *pbuff_in, size_t length, uint32_t cpid,
    char **pbuff_out, size_t *plength)
{
	RTF_WRITER writer;
	GumboOutput *pgumbo_html;

	std::unique_ptr<char[]> buff_inz(new(std::nothrow) char[length+1]);
	if (buff_inz == nullptr)
		return false;
	memcpy(buff_inz.get(), pbuff_in, length);
	buff_inz[length] = '\0';

	*pbuff_out = nullptr;
	auto pbuffer = me_alloc<char>(3 * (length + 1));
	if (NULL == pbuffer) {
		return FALSE;
	}
	html_string_to_utf8(cpid, buff_inz.get(), pbuffer, 3 * length + 1);
	if (!html_init_writer(&writer)) {
		free(pbuffer);
		return FALSE;
	}
	pgumbo_html = gumbo_parse(pbuffer);
	if (NULL == pgumbo_html) {
		free(pbuffer);
		return FALSE;
	}
	if (NULL != pgumbo_html->root) {
		html_enum_tables(&writer, pgumbo_html->root);
		if (!html_write_header(&writer) ||
		    !html_enum_write(&writer, pgumbo_html->root) ||
		    !html_write_tail(&writer)) {
			gumbo_destroy_output(&kGumboDefaultOptions, pgumbo_html);
			free(pbuffer);
			return FALSE;
		}
	}
	*plength = writer.ext_push.m_offset;
	*pbuff_out = me_alloc<char>(*plength);
	if (*pbuff_out != nullptr)
		memcpy(*pbuff_out, writer.ext_push.m_udata, *plength);
	gumbo_destroy_output(&kGumboDefaultOptions, pgumbo_html);
	free(pbuffer);
	return *pbuff_out != nullptr ? TRUE : FALSE;
}
