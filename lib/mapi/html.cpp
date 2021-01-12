// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cctype>
#include <cstdint>
#include <memory>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/html.hpp>
#include <gromox/util.hpp>
#include <gromox/int_hash.hpp>
#include <gromox/str_hash.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/double_list.hpp>
#include <cstdio>
#include <gumbo.h>
#include <iconv.h>
#include <cstdlib>
#include <cstring>
#define RTF_PARAGRAPHALIGN_DEFAULT			0
#define RTF_PARAGRAPHALIGN_LEFT				1
#define RTF_PARAGRAPHALIGN_CENTER			2
#define RTF_PARAGRAPHALIGN_RIGHT			3
#define RTF_PARAGRAPHALIGN_JUSTIFY			4

#define MAX_TABLE_ITEMS						1024

struct COLOR_ITEM {
	const char *name;
	int value;
};

struct FONT_NODE {
	DOUBLE_LIST_NODE node;
	char font_name[128];
	int index;
};

struct COLOR_NODE {
	DOUBLE_LIST_NODE node;
	int color;
	int index;
};

struct RTF_WRITER {
	EXT_PUSH ext_push;
	DOUBLE_LIST font_table;
	STR_HASH_TABLE *pfont_hash;
	INT_HASH_TABLE *pcolor_hash;
	DOUBLE_LIST color_table;
};

static iconv_t g_conv_id;
static STR_HASH_TABLE *g_color_hash;
static CPID_TO_CHARSET html_cpid_to_charset;

static BOOL html_enum_write(RTF_WRITER *pwriter, GumboNode *pnode);

BOOL html_init_library(CPID_TO_CHARSET cpid_to_charset)
{
	int i;
	static const COLOR_ITEM color_map[] =
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
	
	if (NULL == g_color_hash) {
		g_color_hash = str_hash_init(
			sizeof(color_map)/sizeof(COLOR_ITEM) + 1,
			sizeof(int), NULL);
		if (NULL == g_color_hash) {
			return FALSE;
		}
		for (i=0; i<sizeof(color_map)/sizeof(COLOR_ITEM); i++) {
			str_hash_add(g_color_hash,
				color_map[i].name,
				&color_map[i].value);
		}
		g_conv_id = iconv_open("UTF-16LE", "UTF-8");
		if ((iconv_t)-1 == g_conv_id) {
			str_hash_free(g_color_hash);
			g_color_hash = NULL;
			return FALSE;
		}
		html_cpid_to_charset = cpid_to_charset;
	}
	return TRUE;
}

static void html_set_fonttable(RTF_WRITER *pwriter, const char* font_name) 
{
	FONT_NODE tmp_node;
	
	HX_strlcpy(tmp_node.font_name, font_name, GX_ARRAY_SIZE(tmp_node.font_name));
	HX_strlower(tmp_node.font_name);
	auto pfnode = static_cast<FONT_NODE *>(str_hash_query(pwriter->pfont_hash, tmp_node.font_name));
	if (NULL != pfnode) {
		return;
	}
	tmp_node.index = double_list_get_nodes_num(&pwriter->font_table);
	if (1 != str_hash_add(pwriter->pfont_hash,
		tmp_node.font_name, &tmp_node)) {
		return;
	}
	pfnode = static_cast<FONT_NODE *>(str_hash_query(pwriter->pfont_hash, tmp_node.font_name));
	pfnode->node.pdata = pfnode;
	double_list_append_as_tail(&pwriter->font_table, &pfnode->node);
}

static int html_get_fonttable(RTF_WRITER *pwriter, const char* font_name)
{
	char tmp_buff[128];
	
	HX_strlcpy(tmp_buff, font_name, GX_ARRAY_SIZE(tmp_buff));
	HX_strlower(tmp_buff);
	auto pfnode = static_cast<FONT_NODE *>(str_hash_query(pwriter->pfont_hash, tmp_buff));
	if (NULL == pfnode) {
		return -1;
	}
	return pfnode->index;
}

static void html_set_colortable(RTF_WRITER *pwriter, int color) 
{ 
	COLOR_NODE tmp_node;
	
	auto pcnode = static_cast<COLOR_NODE *>(int_hash_query(pwriter->pcolor_hash, color));
	if (NULL != pcnode) {
		return;
	}
	tmp_node.color = color;
	tmp_node.index = double_list_get_nodes_num(&pwriter->color_table);
	if (1 != int_hash_add(pwriter->pcolor_hash, color, &tmp_node)) {
		return;
	}
	pcnode = static_cast<COLOR_NODE *>(int_hash_query(pwriter->pcolor_hash, color));
	pcnode->node.pdata = pcnode;
	double_list_append_as_tail(&pwriter->color_table, &pcnode->node);
}

static int html_get_colortable(RTF_WRITER *pwriter, int color)
{
	auto pcnode = static_cast<COLOR_NODE *>(int_hash_query(pwriter->pcolor_hash, color));
	if (NULL == pcnode) {
		return -1;
	}
	return pcnode->index;
}

static BOOL html_init_writer(RTF_WRITER *pwriter) 
{
	if (FALSE == ext_buffer_push_init(
		&pwriter->ext_push, NULL, 0, 0)) {
		return FALSE;	
	}
	pwriter->pfont_hash = str_hash_init(
		MAX_TABLE_ITEMS, sizeof(FONT_NODE), NULL);
	if (NULL == pwriter->pfont_hash) {
		ext_buffer_push_free(&pwriter->ext_push);
		return FALSE;
	}
	pwriter->pcolor_hash = int_hash_init(MAX_TABLE_ITEMS, sizeof(COLOR_NODE));
	if (NULL == pwriter->pcolor_hash) {
		str_hash_free(pwriter->pfont_hash);
		ext_buffer_push_free(&pwriter->ext_push);
		return FALSE;
	}
	double_list_init(&pwriter->font_table);
	double_list_init(&pwriter->color_table);
	html_set_fonttable(pwriter, "Times New Roman");
	html_set_fonttable(pwriter, "Arial");
	/* first item in font table is for symbol */
	html_set_fonttable(pwriter, "symbol");
	/* first item in color table is for anchor link */
	html_set_colortable(pwriter, 0x0645AD);
	return TRUE;
} 
 
static void html_free_writer(RTF_WRITER *pwriter)
{
	str_hash_free(pwriter->pfont_hash);
	double_list_free(&pwriter->font_table);
	int_hash_free(pwriter->pcolor_hash);
	double_list_free(&pwriter->color_table);
	ext_buffer_push_free(&pwriter->ext_push);
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
	char *pin, *pout;
	
	pin = (char*)src;
	pout = (char*)&wchar;
	in_len = length;
	len = sizeof(uint16_t);
	if (-1 == iconv(g_conv_id, &pin, &in_len,
		&pout, &len) || 0 != len) {
		return 0;
	} else {
		return wchar;
	}
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
				if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
					&pwriter->ext_push, "\\\\", 2)) {
					return FALSE;	
				}
			} else if ('{' == *ptr) {
				if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
					&pwriter->ext_push, "\\{", 2)) {
					return FALSE;
				}
			} else if ('}' == *ptr) {
				if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
					&pwriter->ext_push, "\\}", 2)) {
					return FALSE;
				}
			} else {
				if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
					&pwriter->ext_push, *ptr)) {
					return FALSE;
				}
			}
		} else {
			wchar = html_utf8_to_wchar(ptr, len);
			if (0 == wchar) {
				return FALSE;
			}
			snprintf(tmp_buff, sizeof(tmp_buff), "\\u%hu?", wchar);
			tmp_len = strlen(tmp_buff);
			if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
				&pwriter->ext_push, tmp_buff, tmp_len)) {
				return FALSE;
			}
		}
		ptr += len;
	}
	return TRUE;
}
 
/* writes RTF document header */
static BOOL html_write_header(RTF_WRITER*pwriter)
{
	int length;
	FONT_NODE *pfnode;
	COLOR_NODE *pcnode;
	char tmp_string[256];
	DOUBLE_LIST_NODE *pnode;
	
	length = sprintf(tmp_string,
		"{\\rtf1\\ansi\\fbidis\\ansicpg1252\\deff0");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_string, length)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, "{\\fonttbl", 9)) {
		return FALSE;	
	}
	while ((pnode = double_list_get_from_head(&pwriter->font_table)) != NULL) {
		pfnode = (FONT_NODE*)pnode->pdata;
		if (0 == strcasecmp(pfnode->font_name, "symbol")) {
			length = sprintf(tmp_string,
				"{\\f%d\\fswiss\\fcharset2 ", pfnode->index);
		} else {
			length = sprintf(tmp_string,
				"{\\f%d\\fswiss\\fcharset0 ", pfnode->index);
		}
		if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
			&pwriter->ext_push, tmp_string, length)) {
			return FALSE;
		}
		if (FALSE == html_write_string(pwriter, pfnode->font_name)) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
			&pwriter->ext_push, ";}", 2)) {
			return FALSE;	
		}
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, "}{\\colortbl", 11)) {
		return FALSE;
	}
	while ((pnode = double_list_get_from_head(&pwriter->color_table)) != NULL) {
		pcnode = (COLOR_NODE*)pnode->pdata;
		length = sprintf(tmp_string, "\\red%d\\green%d\\blue%d;",
							(pcnode->color & 0xFF0000) >> 16,
							(pcnode->color & 0xFF00) >> 8,
							pcnode->color & 0xFF);
		if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
			&pwriter->ext_push, tmp_string, length)) {
			return FALSE;
		}
	}
	length = sprintf(tmp_string,
		"}\n{\\*\\generator gromox-rtf;}"
		"\n{\\*\\formatConverter converted from html;}"
		"\\viewkind5\\viewscale100\n{\\*\\bkmkstart BM_BEGIN}");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_string, length)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL html_write_tail(RTF_WRITER*pwriter)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&pwriter->ext_push, '}')) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_style_color(RTF_WRITER *pwriter, int color)
{
	int index;
	int length;
	char tmp_buff[256];
	
	index = html_get_colortable(pwriter, color);
	if (index >= 0) {
		length = sprintf(tmp_buff, "\\cf%d", index);
		if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
			&pwriter->ext_push, tmp_buff, length)) {
			return FALSE;
		}
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
		length = sprintf(tmp_buff, "\\f%d ", index);
		if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
			&pwriter->ext_push, tmp_buff, length)) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL html_write_style_font_size(RTF_WRITER *pwriter,
	int font_size, BOOL unit_point)
{
	int length;
	char tmp_buff[256];
	
	if (FALSE == unit_point) {
		/* 1px = 0.75292857248934pt */
		font_size = (int)(((double)font_size)*0.75292857248934*2);
	} else {
		font_size *= 2;
	}
	length = sprintf(tmp_buff, "\\fs%d ", font_size);
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_style_line_height(RTF_WRITER *pwriter, int line_height)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "\\sl%d ", line_height*15);
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_style_margin_top(RTF_WRITER *pwriter, int margin_top)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "\\sa%d ", margin_top*15);
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_style_text_indent(RTF_WRITER *pwriter, int text_indent)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "\\fi%d ", text_indent*15);
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
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
	int tmp_val;
	const char *ptr;
	const char *ptr1;
	char color_string[128], tmp_buff[8];
	
	if ('#' == value[0]) {
		if (FALSE == decode_hex_binary(
			value + 1, tmp_buff, 3)) {
			return -1;
		}
		color = ((int)tmp_buff[0]) << 16 |
			((int)tmp_buff[1]) << 8 | tmp_buff[2];
		return color;
	}
	if (0 == strncasecmp(value, "rgb(", 4)) {
		ptr = value + 4;
		ptr1 = strchr(ptr, ',');
		if (NULL == ptr1 || ptr1 - ptr >=
			sizeof(tmp_buff)) {
			return -1;
		}
		memcpy(tmp_buff, ptr, ptr1 - ptr);
		tmp_buff[ptr1 - ptr] = '\0';
		tmp_val = atoi(tmp_buff);
		if (tmp_val < 0 || tmp_val > 255) {
			return -1;
		}
		color = tmp_val << 16;
		ptr = ptr1;
		ptr1 = strchr(ptr, ',');
		if (NULL == ptr1 || ptr1 - ptr >=
			sizeof(tmp_buff)) {
			return -1;
		}
		memcpy(tmp_buff, ptr, ptr1 - ptr);
		tmp_buff[ptr1 - ptr] = '\0';
		tmp_val = atoi(tmp_buff);
		if (tmp_val < 0 || tmp_val > 255) {
			return -1;
		}
		color |= tmp_val << 8;
		ptr = ptr1;
		ptr1 = strchr(ptr, ')');
		if (NULL == ptr1 || ptr1 - ptr >=
			sizeof(tmp_buff)) {
			return -1;
		}
		memcpy(tmp_buff, ptr, ptr1 - ptr);
		tmp_buff[ptr1 - ptr] = '\0';
		tmp_val = atoi(tmp_buff);
		if (tmp_val < 0 || tmp_val > 255) {
			return -1;
		}
		color |= tmp_val;
		return color;
	}
	strcpy(color_string, value);
	HX_strlower(color_string);
	auto pcolor = static_cast<int *>(str_hash_query(g_color_hash, color_string));
	if (NULL != pcolor) {
		return *pcolor;
	}
	return -1;
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
	if (TRUE == html_match_style(pattribute->value,
		"font-family", value, sizeof(value))) {
		html_trim_style_value(value);
		if (FALSE == html_write_style_font_family(pwriter, value)) {
			return FALSE;
		}
	}
	if (TRUE == html_match_style(pattribute->value,
		"font-size", value, sizeof(value))) {
		value_len = strlen(value);
		if (0 == strcasecmp(value + value_len - 2, "pt")) {
			unit_point = TRUE;
		} else {
			unit_point = FALSE;
		}
		if (FALSE == html_write_style_font_size(
			pwriter, atoi(value), unit_point)) {
			return FALSE;	
		}
	}
	if (TRUE == html_match_style(pattribute->value,
		"line-height", value, sizeof(value))) {
		value_len = strlen(value);
		if (0 == strcasecmp(value + value_len - 2, "px")) {
			if (FALSE == html_write_style_line_height(
				pwriter, atoi(value))) {
				return FALSE;	
			}
		}
	}
	if (TRUE == html_match_style(pattribute->value,
		"margin-top", value, sizeof(value))) {
		value_len = strlen(value);
		if (0 == strcasecmp(value + value_len - 2, "px")) {
			if (FALSE == html_write_style_margin_top(
				pwriter, atoi(value))) {
				return FALSE;	
			}
		}
	}
	if (TRUE == html_match_style(pattribute->value,
		"text-indent", value, sizeof(value))) {
		value_len = strlen(value);
		if (0 == strcasecmp(value + value_len - 2, "px")) {
			if (FALSE == html_write_style_text_indent(
				pwriter, atoi(value))) {
				return FALSE;
			}
		}
	}
	if (TRUE == html_match_style(pattribute->value,
		"color", value, sizeof(value))) {
		color = html_convert_color(value);
		if (-1 != color) {
			if (FALSE == html_write_style_color(
				pwriter, color)) {
				return FALSE;	
			}
		}
	}
	return TRUE;
}

static BOOL html_write_a_begin(RTF_WRITER *pwriter, const char *link)
{
	char tmp_buff[1024];
	int length = gx_snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff),
			"{\\field{\\*\\fldinst{HYPERLINK %s}}"
			"{\\fldrslt\\cf0 ", link);
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_a_end(RTF_WRITER *pwriter)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, "}}", 2)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL html_write_b_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "{\\b ");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_b_end(RTF_WRITER *pwriter)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&pwriter->ext_push, '}')) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_i_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "{\\i ");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_i_end(RTF_WRITER *pwriter)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&pwriter->ext_push, '}')) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_div_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "{\\pard ");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_div_end(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "\\sb70\\par}");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL html_write_h_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "{\\pard ");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_h_end(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "\\sb70\\par}");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL html_write_p_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "{\\pard ");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_p_end(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "\\sb70\\par}");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL html_write_s_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "{\\strike ");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_s_end(RTF_WRITER *pwriter)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&pwriter->ext_push, '}')) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_em_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "{\\b ");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_em_end(RTF_WRITER *pwriter)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&pwriter->ext_push, '}')) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_ol_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff,
		"{{\\*\\pn\\pnlvlbody\\pnf0\\pnindent0\\pnstart1\\pndec"
		"{\\pntxta.}}\\fi-360\\li720\\sa200\\sl276\\slmult1 ");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_ol_end(RTF_WRITER *pwriter)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&pwriter->ext_push, '}')) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_ul_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff,
		"{{\\*\\pn\\pnlvlblt\\pnf1\\pnindent0{\\pntxtb\\"
		"\'B7}}\\fi-360\\li720\\sa200\\sl276\\slmult1 ");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_ul_end(RTF_WRITER *pwriter)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&pwriter->ext_push, '}')) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL html_write_li_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "{\\pntext\\tab\\f3 \\'b7}");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_li_end(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "\\par\n");
	
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL html_write_center_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "{\\pard\\qr ");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_center_end(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "\\par}");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_table_begin(RTF_WRITER *pwriter)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&pwriter->ext_push, '{')) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL html_write_table_end(RTF_WRITER *pwriter)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&pwriter->ext_push, '}')) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL html_write_span_begin(RTF_WRITER *pwriter)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&pwriter->ext_push, '{')) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL html_write_span_end(RTF_WRITER *pwriter)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&pwriter->ext_push, '}')) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL html_write_font_begin(RTF_WRITER *pwriter)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&pwriter->ext_push, '{')) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL html_write_font_end(RTF_WRITER *pwriter)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&pwriter->ext_push, '}')) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL html_write_mark_begin(RTF_WRITER *pwriter)
{
	int index;
	int length;
	char tmp_buff[256];
	
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&pwriter->ext_push, '{')) {
		return FALSE;
	}
	index = html_get_colortable(pwriter, 0xFFFF00);
	if (index >= 0) {
		length = sprintf(tmp_buff, "\\highlight%d ", index);
		if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
			&pwriter->ext_push, tmp_buff, length)) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL html_write_mark_end(RTF_WRITER *pwriter)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&pwriter->ext_push, '}')) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL html_write_td_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "{\\pard\\intbl\\qc ");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_td_end(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "\\cell}\n");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_th_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "{\\pard\\intbl\\qc ");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_th_end(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "\\cell}\n");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_tr_begin(RTF_WRITER *pwriter, int cell_num)
{
	int i;
	int length;
	double percell;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "{\\trowd\\trgaph10 ");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	if (0 == cell_num) {
		return TRUE;
	}
	percell = 8503/cell_num;
	for (i=0; i<cell_num; i++) {
		length = sprintf(tmp_buff, "\\clbrdrt\\brdrw15\\brdrs"
				"\\clbrdrl\\brdrw15\\brdrs\\clbrdrb\\brdrw15"
				"\\brdrs\\clbrdrr\\brdrw15\\brdrs\\cellx%d\n",
				(int)(percell*(i + 1)));
		if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
			&pwriter->ext_push, tmp_buff, length)) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL html_write_tr_end(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "\\row}\n");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_sub_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "{\\sub ");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_sub_end(RTF_WRITER *pwriter)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&pwriter->ext_push, '}')) {
		return FALSE;
	}
	return TRUE;
}


static BOOL html_write_sup_begin(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "{\\super ");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_sup_end(RTF_WRITER *pwriter)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&pwriter->ext_push, '}')) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_br(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "\\line ");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_hr(RTF_WRITER *pwriter)
{
	int length;
	char tmp_buff[256];
	
	length = sprintf(tmp_buff, "\\pard\\brdrb\\brdrs"
			"\\brdrw10\\brsp20{\\fs4\\~}\\par\\pard ");
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&pwriter->ext_push, tmp_buff, length)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL html_write_children(RTF_WRITER *pwriter, GumboNode *pnode)
{
	unsigned int i;
	
	if (FALSE == html_write_style(pwriter, &pnode->v.element)) {
		return FALSE;
	}
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
			if (NULL == pattribute) {
				pvalue = "";
			} else {
				pvalue = pattribute->value;
			}
			if (FALSE == html_write_a_begin(pwriter, pvalue)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_a_end(pwriter);
		case GUMBO_TAG_B:
			if (FALSE == html_write_b_begin(pwriter)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_b_end(pwriter);
		case GUMBO_TAG_I:
			if (FALSE == html_write_i_begin(pwriter)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_i_end(pwriter);
		case GUMBO_TAG_DIV:
			if (FALSE == html_write_div_begin(pwriter)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_div_end(pwriter);
		case GUMBO_TAG_H1:
		case GUMBO_TAG_H2:
		case GUMBO_TAG_H3:
		case GUMBO_TAG_H4:
		case GUMBO_TAG_H5:
		case GUMBO_TAG_H6:
			if (FALSE == html_write_h_begin(pwriter)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_h_end(pwriter);
		case GUMBO_TAG_P:
			if (FALSE == html_write_p_begin(pwriter)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_p_end(pwriter);
		case GUMBO_TAG_S:
			if (FALSE == html_write_s_begin(pwriter)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_s_end(pwriter);
		case GUMBO_TAG_BR:
			return html_write_br(pwriter);
		case GUMBO_TAG_HR:
			return html_write_hr(pwriter);
		case GUMBO_TAG_EM:
			if (FALSE == html_write_em_begin(pwriter)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_em_end(pwriter);
		case GUMBO_TAG_OL:
			if (FALSE == html_write_ol_begin(pwriter)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_ol_end(pwriter);
		case GUMBO_TAG_UL:
			if (FALSE == html_write_ul_begin(pwriter)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_ul_end(pwriter);
		case GUMBO_TAG_LI:
			if (FALSE == html_write_li_begin(pwriter)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_li_end(pwriter);
		case GUMBO_TAG_CENTER:
			if (FALSE == html_write_center_begin(pwriter)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_center_end(pwriter);
		case GUMBO_TAG_TABLE:
			if (TRUE == html_check_parent_type(pnode, GUMBO_TAG_TABLE)) {
				return TRUE;
			}
			if (FALSE == html_write_table_begin(pwriter)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_table_end(pwriter);
		case GUMBO_TAG_SPAN:
			if (FALSE == html_write_span_begin(pwriter)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_span_end(pwriter);
		case GUMBO_TAG_FONT:
			if (FALSE == html_write_font_begin(pwriter)) {
				return FALSE;
			}
			pattribute = gumbo_get_attribute(
				&pnode->v.element.attributes, "face");
			if (NULL != pattribute) {
				if (FALSE == html_write_style_font_family(
					pwriter, pattribute->value)) {
					return FALSE;	
				}
			}
			pattribute = gumbo_get_attribute(
				&pnode->v.element.attributes, "color");
			if (NULL != pattribute) {
				color = html_convert_color(pattribute->value);
				if (-1 != color) {
					if (FALSE == html_write_style_color(
						pwriter, color)) {
						return FALSE;	
					}
				}
			}
			pattribute = gumbo_get_attribute(
				&pnode->v.element.attributes, "size");
			if (NULL != pattribute) {
				if (FALSE == html_write_style_font_size(
					pwriter, atoi(pattribute->value)*3 + 8,
					FALSE)) {
					return FALSE;	
				}
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_font_end(pwriter);
		case GUMBO_TAG_MARK:
			if (FALSE == html_write_mark_begin(pwriter)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_mark_end(pwriter);
		case GUMBO_TAG_TD:
			if (FALSE == html_write_td_begin(pwriter)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_td_end(pwriter);
		case GUMBO_TAG_TH:
			if (FALSE == html_write_th_begin(pwriter)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_th_end(pwriter);
		case GUMBO_TAG_TR:
			cell_num = 0;
			for (i=0; i<pnode->v.element.children.length; i++) {
				if (GUMBO_NODE_ELEMENT == ((GumboNode*)
					pnode->v.element.children.data[i])->type) {
					cell_num ++;
				}
			}
			if (FALSE == html_write_tr_begin(pwriter, cell_num)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_tr_end(pwriter);
		case GUMBO_TAG_SUB:
			if (FALSE == html_write_sub_begin(pwriter)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_sub_end(pwriter);
		case GUMBO_TAG_SUP:
			if (FALSE == html_write_sup_begin(pwriter)) {
				return FALSE;
			}
			if (FALSE == html_write_children(pwriter, pnode)) {
				return FALSE;
			}
			return html_write_sup_end(pwriter);
		default:
			return html_write_children(pwriter, pnode);
		}
	} else if (GUMBO_NODE_TEXT == pnode->type) {
		if (FALSE == html_check_parent_type(pnode, GUMBO_TAG_STYLE) &&
			FALSE == html_check_parent_type(pnode, GUMBO_TAG_SCRIPT)) {
			return html_write_string(pwriter, pnode->v.text.text);
		}
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
			color = html_convert_color(value);
			if (-1 != color) {
				html_set_colortable(pwriter, color);
			}
		}
	}
	pattribute = gumbo_get_attribute(
		&pnode->v.element.attributes, "style");
	if (NULL != pattribute) {
		if (TRUE == html_match_style(pattribute->value,
			"font-family", value, sizeof(value))) {
			html_trim_style_value(value);
			html_set_fonttable(pwriter, value);
		}
		if (TRUE == html_match_style(pattribute->value,
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
	char *pin, *pout;
	iconv_t conv_id;
	const char *charset;
	
	charset = html_cpid_to_charset(cpid);
	if (NULL == charset) {
		charset = "windows-1252";
	}
	conv_id = iconv_open("UTF-8//IGNORE",
		replace_iconv_charset(charset));
	pin = (char*)src;
	pout = dst;
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
	auto pbuffer = static_cast<char *>(malloc(3 * (length + 1)));
	if (NULL == pbuffer) {
		return FALSE;
	}
	html_string_to_utf8(cpid, buff_inz.get(), pbuffer, 3 * length + 1);
	if (FALSE == html_init_writer(&writer)) {
		free(pbuffer);
		return FALSE;
	}
	pgumbo_html = gumbo_parse(pbuffer);
	if (NULL == pgumbo_html) {
		html_free_writer(&writer);
		free(pbuffer);
		return FALSE;
	}
	if (NULL != pgumbo_html->root) {
		html_enum_tables(&writer, pgumbo_html->root);
		if (FALSE == html_write_header(&writer) ||
			FALSE == html_enum_write(&writer, pgumbo_html->root) ||
			FALSE == html_write_tail(&writer)) {
			gumbo_destroy_output(&kGumboDefaultOptions, pgumbo_html);
			html_free_writer(&writer);
			free(pbuffer);
			return FALSE;
		}
	}
	*plength = writer.ext_push.offset;
	*pbuff_out = static_cast<char *>(malloc(*plength));
	if (*pbuff_out != nullptr)
		memcpy(*pbuff_out, writer.ext_push.data, *plength);
	gumbo_destroy_output(&kGumboDefaultOptions, pgumbo_html);
	html_free_writer(&writer);
	free(pbuffer);
	return *pbuff_out != nullptr ? TRUE : FALSE;
}
