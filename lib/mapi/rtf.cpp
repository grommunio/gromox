// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iconv.h>
#include <string>
#include <unordered_map>
#include <libHX/ctype_helper.h>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/double_list.hpp>
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/int_hash.hpp>
#include <gromox/rtf.hpp>
#include <gromox/scope.hpp>
#include <gromox/simple_tree.hpp>
#include <gromox/str_hash.hpp>
#include <gromox/util.hpp>
#define QRF(expr) do { int klfdv = (expr); if (klfdv != EXT_ERR_SUCCESS) return false; } while (false)

#define MAX_ATTRS						10000
#define MAX_GROUP_DEPTH					1000
#define MAX_COLORS						1024
#define MAX_FONTS						1024
#define MAX_CONTROL_LEN					50
#define MAX_FINTNAME_LEN				64

#define DEFAULT_FONT_STR				"Times,TimesRoman,TimesNewRoman"

#define FONTNIL_STR						"Times,TimesRoman,TimesNewRoman"
#define FONTROMAN_STR					"Times,Palatino"
#define FONTSWISS_STR					"Helvetica,Arial"
#define FONTMODERN_STR					"Courier,Verdana"
#define FONTSCRIPT_STR					"Cursive,ZapfChancery"
#define FONTDECOR_STR					"ZapfChancery"
#define FONTTECH_STR					"Symbol"

#define TAG_COMMENT_BEGIN				"<!--"
#define TAG_COMMENT_END					"-->"
#define TAG_DOCUMENT_BEGIN				"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\r\n<html>\r\n"
#define TAG_DOCUMENT_END				"</html>\r\n"
#define TAG_HEADER_BEGIN				"<head>\r\n"
#define TAG_HEADER_END					"</head>\r\n"
#define TAG_DOCUMENT_TITLE_BEGIN		"<title>"
#define TAG_DOCUMENT_TITLE_END			"</title>\r\n"
#define TAG_DOCUMENT_AUTHOR_BEGIN		"<meta name=\"author\" content=\""
#define TAG_DOCUMENT_AUTHOR_END			"\">\r\n"
#define TAG_DOCUMENT_CHANGEDATE_BEGIN	"<!-- changed:"
#define TAG_DOCUMENT_CHANGEDATE_END		"-->\r\n"
#define TAG_BODY_BEGIN					"<body>\r\n"
#define TAG_BODY_END					"</body>\r\n"
#define TAG_PARAGRAPH_BEGIN				"<p>"
#define TAG_PARAGRAPH_END				"</p>\r\n"
#define TAG_CENTER_BEGIN				"<center>"
#define TAG_CENTER_END					"</center>\r\n"
#define TAG_JUSTIFY_BEGIN				"<div align=\"justify\">\r\n"
#define TAG_JUSTIFY_END					"</div>\r\n"
#define TAG_ALIGN_LEFT_BEGIN			"<div align=\"left\">\r\n"
#define TAG_ALIGN_LEFT_END				"</div>\r\n"
#define TAG_ALIGN_RIGHT_BEGIN			"<div align=\"right\">\r\n"
#define TAG_ALIGN_RIGHT_END				"</div>\r\n"
#define TAG_FORCED_SPACE				"&nbsp;"
#define TAG_LINE_BREAK					"<br>"
#define TAG_PAGE_BREAK					"<p><hr><p>\r\n"
#define TAG_HYPERLINK_BEGIN				"<a href=%s>"
#define TAG_HYPERLINK_END				"</a>"
#define TAG_IMAGELINK_BEGIN				"<img src=\""
#define TAG_IMAGELINK_END				"\">"
#define TAG_TABLE_BEGIN					"<table border=\"2\">\r\n"
#define TAG_TABLE_END					"</table>\r\n"
#define TAG_TABLE_ROW_BEGIN				"<tr>\r\n"
#define TAG_TABLE_ROW_END				"</tr>\r\n"
#define TAG_TABLE_CELL_BEGIN			"<td>\r\n"
#define TAG_TABLE_CELL_END				"</td>\r\n"
#define TAG_FONT_BEGIN					"<font face=\"%s\">"
#define TAG_FONT_END					"</font>\r\n"
#define TAG_FONTSIZE_BEGIN				"<span style=\"font-size:%dpt\">"
#define TAG_FONTSIZE_END				"</span>"
#define TAG_FONTSIZE8_BEGIN				"<font size=\"1\">"
#define TAG_FONTSIZE8_END				"</font>"
#define TAG_FONTSIZE10_BEGIN			"<font size=\"2\">"
#define TAG_FONTSIZE10_END				"</font>"
#define TAG_FONTSIZE12_BEGIN			"<font size=\"3\">"
#define TAG_FONTSIZE12_END				"</font>"
#define TAG_FONTSIZE14_BEGIN			"<font size=\"4\">"
#define TAG_FONTSIZE14_END				"</font>"
#define TAG_FONTSIZE18_BEGIN			"<font size=\"5\">"
#define TAG_FONTSIZE18_END				"</font>"
#define TAG_FONTSIZE24_BEGIN			"<font size=\"6\">"
#define TAG_FONTSIZE24_END				"</font>"
#define TAG_SMALLER_BEGIN				"<small>"
#define TAG_SMALLER_END					"</small>"
#define TAG_BIGGER_BEGIN				"<big>"
#define TAG_BIGGER_END					"</big>"
#define TAG_FOREGROUND_BEGIN			"<font color=\"#%06x\">"
#define TAG_FOREGROUND_END				"</font>"
#define TAG_BACKGROUND_BEGIN			"<span style=\"background:#%06x\">"
#define TAG_BACKGROUND_END				"</span>"
#define TAG_BOLD_BEGIN					"<b>"
#define TAG_BOLD_END					"</b>"
#define TAG_ITALIC_BEGIN				"<i>"
#define TAG_ITALIC_END					"</i>"
#define TAG_UNDERLINE_BEGIN				"<u>"
#define TAG_UNDERLINE_END				"</u>"
#define TAG_DBL_UNDERLINE_BEGIN			"<u>"
#define TAG_DBL_UNDERLINE_END			"</u>"
#define TAG_SUPERSCRIPT_BEGIN			"<sup>"
#define TAG_SUPERSCRIPT_END				"</sup>"
#define TAG_SUBSCRIPT_BEGIN				"<sub>"
#define TAG_SUBSCRIPT_END				"</sub>"
#define TAG_STRIKETHRU_BEGIN			"<s>"
#define TAG_STRIKETHRU_END				"</s>"
#define TAG_DBL_STRIKETHRU_BEGIN		"<s>"
#define TAG_DBL_STRIKETHRU_END			"</s>"
#define TAG_EMBOSS_BEGIN				"<span style=\"background:gray\"><font color=\"black\">"
#define TAG_EMBOSS_END					"</font></span>"
#define TAG_ENGRAVE_BEGIN				"<span style=\"background:gray\"><font color=\"navyblue\">"
#define TAG_ENGRAVE_END					"</font></span>"
#define TAG_SHADOW_BEGIN				"<span style=\"background:gray\">"
#define TAG_SHADOW_END					"</span>"
#define TAG_OUTLINE_BEGIN				"<span style=\"background:gray\">"
#define TAG_OUTLINE_END					"</span>"
#define TAG_EXPAND_BEGIN				"<span style=\"letter-spacing: %d\">"
#define TAG_EXPAND_END					"</span>"
#define TAG_POINTLIST_BEGIN				"<ol>\r\n"
#define TAG_POINTLIST_END				"</ol>\r\n"
#define TAG_POINTLIST_ITEM_BEGIN		"<li>\r\n"
#define TAG_POINTLIST_ITEM_END			"</li>\r\n"
#define TAG_NUMERICLIST_BEGIN			"<ul>\r\n"
#define TAG_NUMERICLIST_END				"</ul>\r\n"
#define TAG_NUMERICLIST_ITEM_BEGIN		"<li>\r\n"
#define TAG_NUMERICLIST_ITEM_END		"</li>\r\n"
#define TAG_UNISYMBOL_PRINT				"&#%d;"
#define TAG_HTML_CHARSET				"<meta http-equiv=\"content-type\" content=\"text/html; charset=%s\">\r\n"
#define TAG_CHARS_RIGHT_QUOTE			"&rsquo;"
#define TAG_CHARS_LEFT_QUOTE			"&lsquo;"
#define TAG_CHARS_RIGHT_DBL_QUOTE		"&rdquo;"
#define TAG_CHARS_LEFT_DBL_QUOTE		"&ldquo;"
#define TAG_CHARS_ENDASH				"&ndash;"
#define TAG_CHARS_EMDASH				"&mdash;"
#define TAG_CHARS_BULLET				"&bull;"
#define TAG_CHARS_NONBREAKING_SPACE		"&nbsp;"
#define TAG_CHARS_SOFT_HYPHEN			"&shy;"

using namespace gromox;

enum {
	ATTR_NONE = 0,
	ATTR_BOLD,
	ATTR_ITALIC,
	ATTR_UNDERLINE,
	ATTR_DOUBLE_UL,
	ATTR_WORD_UL, 
	ATTR_THICK_UL,
	ATTR_WAVE_UL, 
	ATTR_DOT_UL,
	ATTR_DASH_UL,
	ATTR_DOT_DASH_UL,
	ATTR_2DOT_DASH_UL,
	ATTR_FONTSIZE,
	ATTR_STD_FONTSIZE,
	ATTR_FONTFACE,
	ATTR_FOREGROUND,
	ATTR_BACKGROUND,
	ATTR_CAPS,
	ATTR_SMALLCAPS,
	ATTR_PICT,
	ATTR_SHADOW,
	ATTR_OUTLINE, 
	ATTR_EMBOSS, 
	ATTR_ENGRAVE, 
	ATTR_SUPER,
	ATTR_SUB, 
	ATTR_STRIKE, 
	ATTR_DBL_STRIKE, 
	ATTR_EXPAND,
	ATTR_UBYTES,
	ATTR_HTMLTAG
};

enum {
	ALIGN_LEFT = 0,
	ALIGN_RIGHT,
	ALIGN_CENTER,
	ALIGN_JUSTIFY
};

enum {
	PICT_UNKNOWN = 0,
	PICT_WM,
	PICT_MAC,
	PICT_PM,
	PICT_DI,
	PICT_WB,
	PICT_JPEG,
	PICT_PNG,
	PICT_EMF
};

namespace {

struct COLLECTION_NODE {
	DOUBLE_LIST_NODE node;
	int nr;
	char *text;
};

struct ATTRSTACK_NODE {
	DOUBLE_LIST_NODE node;
	uint8_t attr_stack[MAX_ATTRS];
	int attr_params[MAX_ATTRS];
	int tos;
};

struct FONTENTRY {
	char name[MAX_FINTNAME_LEN];
	char encoding[32];
};

struct RTF_READER {
	RTF_READER() = default;
	~RTF_READER();
	NOMOVE(RTF_READER);

	bool is_within_table = false, b_printed_row_begin = false;
	bool b_printed_cell_begin = false, b_printed_row_end = false;
	bool b_printed_cell_end = false, b_simulate_smallcaps = false;
	bool b_simulate_allcaps = false, b_ubytes_switch = false;
	bool is_within_picture = false, have_printed_body = false;
	bool is_within_header = true, have_ansicpg = false;
	bool have_fromhtml = false, is_within_htmltag = false;
	bool is_within_htmlrtf = false;
	int coming_pars_tabular = 0, ubytes_num = 0, ubytes_left = 0;
	int picture_file_number = 1;
	char picture_path[256]{};
	int picture_width = 0, picture_height = 0, picture_bits_per_pixel = 1;
	int picture_type = 0, picture_wmf_type = 0;
	const char *picture_wmf_str = nullptr;
	int color_table[MAX_COLORS]{}, total_colors = 0;
	int total_chars_in_line = 0;
	char default_encoding[32] = "windows-1252", current_encoding[32]{};
	char html_charset[32]{};
	int default_font_number = 0;
	std::unique_ptr<INT_HASH_TABLE> pfont_hash;
	DOUBLE_LIST attr_stack_list{};
	EXT_PULL ext_pull{};
	EXT_PUSH ext_push{};
	int ungot_chars[3] = {-1, -1, -1}, last_returned_ch = 0;
	iconv_t conv_id{iconv_t(-1)};
	EXT_PUSH iconv_push{};
	SIMPLE_TREE element_tree{};
	ATTACHMENT_LIST *pattachments = nullptr;
};

struct GROUP_NODE {
	SIMPLE_TREE_NODE node;
	DOUBLE_LIST collection_list;
};

}

enum {
	CMD_RESULT_ERROR = -1,
	CMD_RESULT_CONTINUE,
	CMD_RESULT_IGNORE_REST,
	CMD_RESULT_HYPERLINKED
};

using CMD_PROC_FUNC = int (*)(RTF_READER *, SIMPLE_TREE_NODE *, int, bool, int);

static std::unordered_map<std::string_view, CMD_PROC_FUNC> g_cmd_hash;
static const char* (*rtf_cpid_to_charset)(uint32_t cpid);
static bool rtf_starting_body(RTF_READER *preader);
static bool rtf_starting_text(RTF_READER *preader);

static int rtf_decode_hex_char(const char *in)
{
	int retval;
	
	if (strlen(in) < 2) {
		return 0;
	}
	if (in[0] >= '0' && in[0] <= '9') {
		retval = in[0] - '0';
	} else if ((in[0] >= 'a' && in[0] <= 'f')) {
		retval = in[0] - 'a' + 10;
	} else if (in[0] >= 'A' && in[0] <= 'F') {
		retval = in[0] - 'A' + 10;
	} else {
		return 0;
	}
	retval <<= 4;
	if (in[1] >= '0' && in[1] <= '9') {
		retval += in[1] - '0';
	} else if ((in[1] >= 'a' && in[1] <= 'f')) {
		retval += in[1] - 'a' + 10;
	} else if (in[1] >= 'A' && in[1] <= 'F') {
		retval += in[1] - 'A' + 10;
	} else {
		return 0;
	}
	return retval;
}

static inline CMD_PROC_FUNC rtf_find_cmd_function(const char *cmd)
{
	auto i = g_cmd_hash.find(cmd);
	return i != g_cmd_hash.cend() ? i->second : nullptr;
}

static bool rtf_iconv_open(RTF_READER *preader, const char *fromcode)
{
	if ('\0' == fromcode[0] || 0 == strcasecmp(
		preader->current_encoding, fromcode)) {
		return true;
	}
	if ((iconv_t)-1 != preader->conv_id) {
		iconv_close(preader->conv_id);
		preader->conv_id = (iconv_t)-1;
	}
	preader->conv_id = iconv_open("UTF-8//TRANSLIT",
			replace_iconv_charset(fromcode));
	if ((iconv_t)-1 == preader->conv_id) {
		return false;
	}
	gx_strlcpy(preader->current_encoding, fromcode, GX_ARRAY_SIZE(preader->current_encoding));
	return true;
}

static bool rtf_escape_output(RTF_READER *preader, char *string)
{
	int i;
	int tmp_len;
	
	tmp_len = strlen(string);
	if (preader->is_within_htmltag) {
		QRF(preader->ext_push.p_bytes(string, tmp_len));
		return true;
	}
	if (preader->b_simulate_allcaps)
		HX_strupper(string);
	if (preader->b_simulate_smallcaps)
		HX_strlower(string);
	for (i=0; i<tmp_len; i++) {
		switch (string[i]) {
		case '<':
			QRF(preader->ext_push.p_bytes("&lt;", 4));
			break;
		case '>':
			QRF(preader->ext_push.p_bytes("&gt;", 4));
			break;
		case '&':
			QRF(preader->ext_push.p_bytes("&amp;", 5));
			break;
		default:
			QRF(preader->ext_push.p_uint8(string[i]));
			break;
		}
	}
	return true;
}

static bool rtf_flush_iconv_cache(RTF_READER *preader)
{
	char *out_buff;
	size_t out_size;
	
	if (preader->iconv_push.m_offset == 0)
		return true;
	if ((iconv_t)-1 == preader->conv_id) {
		if ('\0' == preader->default_encoding[0]) {
			if (!rtf_iconv_open(preader, "windows-1252"))
				return false;
		} else {
			if (!rtf_iconv_open(preader, preader->default_encoding))
				return false;
		}
	}
	size_t tmp_len = 4 * preader->iconv_push.m_offset;
	auto ptmp_buff = me_alloc<char>(tmp_len);
	if (NULL == ptmp_buff) {
		return false;
	}
	auto in_buff = preader->iconv_push.m_cdata;
	size_t in_size = preader->iconv_push.m_offset;
	out_buff = ptmp_buff;
	out_size = tmp_len;
	if (iconv(preader->conv_id, &in_buff, &in_size, &out_buff, &out_size) == static_cast<size_t>(-1)) {
		free(ptmp_buff);
		/* ignore the characters which can not be converted */
		preader->iconv_push.m_offset = 0;
		return true;
	}
	tmp_len -= out_size;
	ptmp_buff[tmp_len] = '\0';
	if (!rtf_escape_output(preader, ptmp_buff)) {
		free(ptmp_buff);
		return false;
	}
	free(ptmp_buff);
	preader->iconv_push.m_offset = 0;
	return true;
}

static const char *rtf_cpid_to_encoding(uint32_t num)
{
	const char *encoding;
	encoding = rtf_cpid_to_charset(num);
	return encoding != nullptr ? encoding : "windows-1252";
}

static int rtf_parse_control(const char *string,
	char *name, int maxlen, int *pnum)
{
    int len;
	
	if (('*' == string[0] || '~' == string[0] ||
		'_' == string[0] || '-' == string[0]) &&
		'\0' == string[1]) {
		name[0] = '*';
		name[1] = '\0';
		return 0;
	}
	len = 0;
	while (HX_isalpha(*string) && len < maxlen) {
        *name = *string;
		name ++;
		string ++;
        len ++;
    }
    if (len == maxlen) {
        return -1;
	}
    *name = '\0';
    if ('\0' == *string) {
        return 0;
	}
	if (*string != '-' && !HX_isdigit(*string))
        return -1;
	*pnum = strtol(string, nullptr, 0);
    return 1;
}

static uint32_t rtf_fcharset_to_cpid(int num)
{
    switch (num) {
		case 0: return 1252;
		case 1: return 0;
		case 2: return 42; 
		case 77: return 10000;
		case 78: return 10001;
		case 79: return 10003;
		case 80: return 10008;
		case 81: return 10002;
		case 83: return 10005;
		case 84: return 10004;
		case 85: return 10006;
		case 86: return 10081;
		case 87: return 10021;
		case 88: return 10029;
		case 89: return 10007;
		case 128: return 932;
		case 129: return 949;
		case 130: return 1361;
		case 134: return 936;
		case 136: return 950;
		case 161: return 1253;
		case 162: return 1254;
		case 163: return 1258;
		case 177: return 1255;
		case 178: return 1256;
		case 186: return 1257;
		case 204: return 1251;
		case 222: return 874;
		case 238: return 1250;
		case 254: return 437;
    }
	return 1252;
}

static const FONTENTRY *rtf_lookup_font(RTF_READER *preader, int num)
{
	static constexpr FONTENTRY fake_entries[] =
		{{FONTNIL_STR, ""}, {FONTROMAN_STR, ""},
		{FONTSWISS_STR, ""}, {FONTMODERN_STR, ""},
		{FONTSCRIPT_STR, ""}, {FONTDECOR_STR, ""},
		{FONTTECH_STR, ""}};
	
	if (num < 0) {
		return &fake_entries[-num-1];
	}
	return preader->pfont_hash->query<FONTENTRY>(num);
}

static bool rtf_add_to_collection(DOUBLE_LIST *plist, int nr, const char *text)
{
	char *ptext;
	DOUBLE_LIST_NODE *pnode;

	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		auto pcollection = static_cast<COLLECTION_NODE *>(pnode->pdata);
		if (nr == pcollection->nr) {
			ptext = strdup(text);
			if (NULL == ptext) {
				return false;
			}
			free(pcollection->text);
			pcollection->text = ptext;
			return true;
		}
	}
	auto pcollection = me_alloc<COLLECTION_NODE>();
	if (NULL == pcollection) {
		return false;
	}
	pcollection->node.pdata = pcollection;
	pcollection->nr = nr;
	pcollection->text = strdup(text);
	if (NULL == pcollection->text) {
		free(pcollection->text);
		return false;
	}
	double_list_append_as_tail(plist, &pcollection->node);
	return true;
}

static const char * rtf_get_from_collection(DOUBLE_LIST *plist, int nr)
{
	DOUBLE_LIST_NODE *pnode;
	COLLECTION_NODE *pcollection;

	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		pcollection = (COLLECTION_NODE*)pnode->pdata;
		if (nr == pcollection->nr) {
			return pcollection->text;
		}
	}
	return NULL;
}

static void rtf_free_collection(DOUBLE_LIST *plist)
{
	DOUBLE_LIST_NODE *pnode;
	COLLECTION_NODE *pcollection;

	while ((pnode = double_list_pop_front(plist)) != nullptr) {
		pcollection = (COLLECTION_NODE*)pnode->pdata;
		free(pcollection->text);
		free(pcollection);
	}
}

static bool rtf_init_reader(RTF_READER *preader, const char *prtf_buff,
    uint32_t rtf_length, ATTACHMENT_LIST *pattachments)
{
	double_list_init(&preader->attr_stack_list);
	preader->ext_pull.init(prtf_buff, rtf_length, [](size_t) -> void * { return nullptr; }, 0);
	preader->pfont_hash = INT_HASH_TABLE::create(MAX_FONTS, sizeof(FONTENTRY));
	if (NULL == preader->pfont_hash) {
		return false;
	}
	if (!preader->ext_push.init(nullptr, 0, 0) ||
	    !preader->iconv_push.init(nullptr, 0, 0))
		return false;
	simple_tree_init(&preader->element_tree);
	preader->pattachments = pattachments;
	return true;
}

static void rtf_delete_tree_node(SIMPLE_TREE_NODE *pnode)
{
	if (NULL != pnode->pdata) {
		free(pnode->pdata);
	} else {
		auto gn = containerof(pnode, GROUP_NODE, node);
		rtf_free_collection(&gn->collection_list);
		double_list_free(&gn->collection_list);
	}
	free(pnode);
}

RTF_READER::~RTF_READER()
{
	auto preader = this;
	DOUBLE_LIST_NODE *pnode;
	ATTRSTACK_NODE *pattrstack;
	
	preader->pfont_hash.reset();
	while ((pnode = double_list_pop_front(&preader->attr_stack_list)) != nullptr) {
		pattrstack = (ATTRSTACK_NODE*)pnode->pdata;
		free(pattrstack);
	}
	double_list_free(&preader->attr_stack_list);
	auto proot = preader->element_tree.get_root();
	if (NULL != proot) {
		preader->element_tree.destroy_node(proot, rtf_delete_tree_node);
	}
	preader->element_tree.clear();
	if ((iconv_t)-1 != preader->conv_id) {
		iconv_close(preader->conv_id);
	}
}

static bool rtf_express_begin_fontsize(RTF_READER *preader, int size)
{
	int tmp_len;
	char tmp_buff[128];
	
	switch (size) {
	case 8:
		QRF(preader->ext_push.p_bytes(TAG_FONTSIZE8_BEGIN, sizeof(TAG_FONTSIZE8_BEGIN) - 1));
		return true;
	case 10:
		QRF(preader->ext_push.p_bytes(TAG_FONTSIZE10_BEGIN, sizeof(TAG_FONTSIZE10_BEGIN) - 1));
		return true;
	case 12:
		QRF(preader->ext_push.p_bytes(TAG_FONTSIZE12_BEGIN, sizeof(TAG_FONTSIZE12_BEGIN) - 1));
		return true;
	case 14:
		QRF(preader->ext_push.p_bytes(TAG_FONTSIZE14_BEGIN, sizeof(TAG_FONTSIZE14_BEGIN) - 1));
		return true;
	case 18:
		QRF(preader->ext_push.p_bytes(TAG_FONTSIZE18_BEGIN, sizeof(TAG_FONTSIZE18_BEGIN) - 1));
		return true;
	case 24:
		QRF(preader->ext_push.p_bytes(TAG_FONTSIZE24_BEGIN, sizeof(TAG_FONTSIZE24_BEGIN) - 1));
		return true;
	}
	tmp_len = snprintf(tmp_buff, arsizeof(tmp_buff), TAG_FONTSIZE_BEGIN, size);
	QRF(preader->ext_push.p_bytes(tmp_buff, tmp_len));
	return true;
}

static bool rtf_express_end_fontsize(RTF_READER *preader, int size)
{
	switch (size) {
	case 8:
		QRF(preader->ext_push.p_bytes(TAG_FONTSIZE8_END, sizeof(TAG_FONTSIZE8_END) - 1));
		return true;
	case 10:
		QRF(preader->ext_push.p_bytes(TAG_FONTSIZE10_END, sizeof(TAG_FONTSIZE10_END) - 1));
		return true;
	case 12:
		QRF(preader->ext_push.p_bytes(TAG_FONTSIZE12_END, sizeof(TAG_FONTSIZE12_END) - 1));
		return true;
	case 14:
		QRF(preader->ext_push.p_bytes(TAG_FONTSIZE14_END, sizeof(TAG_FONTSIZE14_END) - 1));
		return true;
	case 18:
		QRF(preader->ext_push.p_bytes(TAG_FONTSIZE18_END, sizeof(TAG_FONTSIZE18_END) - 1));
		return true;
	case 24:
		QRF(preader->ext_push.p_bytes(TAG_FONTSIZE24_END, sizeof(TAG_FONTSIZE24_END) - 1));
		return true;
	}
	QRF(preader->ext_push.p_bytes(TAG_FONTSIZE_END, sizeof(TAG_FONTSIZE_END) - 1));
	return true;
}

static bool rtf_express_attr_begin(RTF_READER *preader, int attr, int param)
{
	int tmp_len;
	const char *encoding;
	const FONTENTRY *pentry;
	char tmp_buff[256];
	
	switch (attr) {
	case ATTR_BOLD:
		QRF(preader->ext_push.p_bytes(TAG_BOLD_BEGIN, sizeof(TAG_BOLD_BEGIN) - 1));
		return true;
	case ATTR_ITALIC:
		QRF(preader->ext_push.p_bytes(TAG_ITALIC_BEGIN, sizeof(TAG_ITALIC_BEGIN) - 1));
		return true;
	case ATTR_THICK_UL:
	case ATTR_WAVE_UL:
	case ATTR_DASH_UL:
	case ATTR_DOT_UL:
	case ATTR_DOT_DASH_UL:
	case ATTR_2DOT_DASH_UL:
	case ATTR_WORD_UL:
	case ATTR_UNDERLINE:
		QRF(preader->ext_push.p_bytes(TAG_UNDERLINE_BEGIN, sizeof(TAG_UNDERLINE_BEGIN) - 1));
		return true;
	case ATTR_DOUBLE_UL:
		QRF(preader->ext_push.p_bytes(TAG_DBL_UNDERLINE_BEGIN, sizeof(TAG_DBL_UNDERLINE_BEGIN) - 1));
		return true;
	case ATTR_FONTSIZE:
		return rtf_express_begin_fontsize(preader, param);
	case ATTR_FONTFACE:
		pentry = rtf_lookup_font(preader, param);
		if (NULL == pentry) {
			encoding = preader->default_encoding;
			debug_info("[rtf]: invalid font number %d", param);
			tmp_len = gx_snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff),
				TAG_FONT_BEGIN, DEFAULT_FONT_STR);
		} else {
			encoding = pentry->encoding;
			tmp_len = gx_snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff),
				TAG_FONT_BEGIN, pentry->name);
		}
		if (!preader->have_fromhtml) {
			QRF(preader->ext_push.p_bytes(tmp_buff, tmp_len));
		}
		if (!rtf_iconv_open(preader, encoding))
			return false;
		return true;
	case ATTR_FOREGROUND:
		tmp_len = gx_snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff),
			TAG_FOREGROUND_BEGIN, param);
		QRF(preader->ext_push.p_bytes(tmp_buff, tmp_len));
		return true;
	case ATTR_BACKGROUND: 
		tmp_len = gx_snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff),
			TAG_BACKGROUND_BEGIN, param);
		QRF(preader->ext_push.p_bytes(tmp_buff, tmp_len));
		return true;
	case ATTR_SUPER:
		QRF(preader->ext_push.p_bytes(TAG_SUPERSCRIPT_BEGIN, sizeof(TAG_SUPERSCRIPT_BEGIN) - 1));
		return true;
	case ATTR_SUB:
		QRF(preader->ext_push.p_bytes(TAG_SUBSCRIPT_BEGIN, sizeof(TAG_SUBSCRIPT_BEGIN) - 1));
		return true;
	case ATTR_STRIKE:
		QRF(preader->ext_push.p_bytes(TAG_STRIKETHRU_BEGIN, sizeof(TAG_STRIKETHRU_BEGIN) - 1));
		return true;
	case ATTR_DBL_STRIKE:
		QRF(preader->ext_push.p_bytes(TAG_DBL_STRIKETHRU_BEGIN, sizeof(TAG_DBL_STRIKETHRU_BEGIN) - 1));
		return true;
	case ATTR_EXPAND:
		QRF(preader->ext_push.p_bytes(TAG_EXPAND_BEGIN, sizeof(TAG_EXPAND_BEGIN) - 1));
		return true;
	case ATTR_OUTLINE:
		QRF(preader->ext_push.p_bytes(TAG_OUTLINE_BEGIN, sizeof(TAG_OUTLINE_BEGIN) - 1));
		return true;
	case ATTR_SHADOW:
		QRF(preader->ext_push.p_bytes(TAG_SHADOW_BEGIN, sizeof(TAG_SHADOW_BEGIN) - 1));
		return true;
	case ATTR_EMBOSS:
		QRF(preader->ext_push.p_bytes(TAG_EMBOSS_BEGIN, sizeof(TAG_EMBOSS_BEGIN) - 1));
		return true;
	case ATTR_ENGRAVE:
		QRF(preader->ext_push.p_bytes(TAG_ENGRAVE_BEGIN, sizeof(TAG_ENGRAVE_BEGIN) - 1));
		return true;
	case ATTR_CAPS:
		preader->b_simulate_allcaps = true;
		return true;
	case ATTR_SMALLCAPS:
		preader->b_simulate_smallcaps = true;
		QRF(preader->ext_push.p_bytes(TAG_SMALLER_BEGIN, sizeof(TAG_SMALLER_BEGIN) - 1));
		return true;
	case ATTR_UBYTES:
		preader->b_ubytes_switch = true;
		preader->ubytes_num = param;
		preader->ubytes_left = 0;
		return true;
	case ATTR_PICT:
		preader->is_within_picture = true;
		return true;
	case ATTR_HTMLTAG:
		preader->is_within_htmltag = true;
		if (!rtf_iconv_open(preader, preader->default_encoding))
			return false;
		break;
	}
	return true;
}

static int* rtf_stack_list_find_attr(RTF_READER *preader, int attr)
{
	int i;
	DOUBLE_LIST_NODE *pnode;
	ATTRSTACK_NODE *pattrstack;
	
	pnode = double_list_get_tail(&preader->attr_stack_list);
	pattrstack = (ATTRSTACK_NODE*)pnode->pdata;
	for (i=pattrstack->tos-1; i>=0; i--) {
		if (attr == pattrstack->attr_stack[i]) {
			return &pattrstack->attr_params[i];
		}
	}
	while ((pnode = double_list_get_before(&preader->attr_stack_list, pnode)) != NULL) {
		pattrstack = (ATTRSTACK_NODE*)pnode->pdata;
		for (i=pattrstack->tos; i>=0; i--) {
			if (attr == pattrstack->attr_stack[i]) {
				return &pattrstack->attr_params[i];
			}
		}
	}
	return NULL;
}

static bool rtf_express_attr_end(RTF_READER *preader, int attr, int param)
{
	int *pparam;
	const char *encoding;
	
	switch (attr) {
	case ATTR_BOLD:
		QRF(preader->ext_push.p_bytes(TAG_BOLD_END, sizeof(TAG_BOLD_END) - 1));
		return true;
	case ATTR_ITALIC:
		QRF(preader->ext_push.p_bytes(TAG_ITALIC_END, sizeof(TAG_ITALIC_END) - 1));
		return true;
	case ATTR_THICK_UL:
	case ATTR_WAVE_UL:
	case ATTR_DASH_UL:
	case ATTR_DOT_UL:
	case ATTR_DOT_DASH_UL:
	case ATTR_2DOT_DASH_UL:
	case ATTR_WORD_UL:
	case ATTR_UNDERLINE:
		QRF(preader->ext_push.p_bytes(TAG_UNDERLINE_END, sizeof(TAG_UNDERLINE_END) - 1));
		return true;
	case ATTR_DOUBLE_UL:
		QRF(preader->ext_push.p_bytes(TAG_DBL_UNDERLINE_END, sizeof(TAG_DBL_UNDERLINE_END) - 1));
		return true;
	case ATTR_FONTSIZE:
		return rtf_express_end_fontsize(preader, param);
	case ATTR_FONTFACE: 
		if (!preader->have_fromhtml) {
			QRF(preader->ext_push.p_bytes(TAG_FONT_END, sizeof(TAG_FONT_END) - 1));
		}
		/* Caution: no BREAK here */
	case ATTR_HTMLTAG:
		if (ATTR_HTMLTAG == attr) {
			preader->is_within_htmltag = false;
		}
		pparam = rtf_stack_list_find_attr(preader, ATTR_FONTFACE);
		if (NULL == pparam) {
			encoding = preader->default_encoding;
		} else {
			const FONTENTRY *pentry = rtf_lookup_font(preader, *pparam);
			if (NULL == pentry) {
				encoding = preader->default_encoding;
			} else {
				encoding = pentry->encoding;
			}
		}
		if (!rtf_iconv_open(preader, encoding))
			return false;
		return true;
	case ATTR_FOREGROUND:
		QRF(preader->ext_push.p_bytes(TAG_FOREGROUND_END, sizeof(TAG_FOREGROUND_END) - 1));
		return true;
	case ATTR_BACKGROUND:
		QRF(preader->ext_push.p_bytes(TAG_BACKGROUND_END, sizeof(TAG_BACKGROUND_END) - 1));
		return true;
	case ATTR_SUPER:
		QRF(preader->ext_push.p_bytes(TAG_SUPERSCRIPT_END, sizeof(TAG_SUPERSCRIPT_END) - 1));
		return true;
	case ATTR_SUB:
		QRF(preader->ext_push.p_bytes(TAG_SUBSCRIPT_END, sizeof(TAG_SUBSCRIPT_END) - 1));
		return true;
	case ATTR_STRIKE:
		QRF(preader->ext_push.p_bytes(TAG_STRIKETHRU_END, sizeof(TAG_STRIKETHRU_END) - 1));
		return true;
	case ATTR_DBL_STRIKE:
		QRF(preader->ext_push.p_bytes(TAG_DBL_STRIKETHRU_END, sizeof(TAG_DBL_STRIKETHRU_END) - 1));
		return true;
	case ATTR_OUTLINE:
		QRF(preader->ext_push.p_bytes(TAG_OUTLINE_END, sizeof(TAG_OUTLINE_END) - 1));
		return true;
	case ATTR_SHADOW:
		QRF(preader->ext_push.p_bytes(TAG_SHADOW_END, sizeof(TAG_SHADOW_END) - 1));
		return true;
	case ATTR_EMBOSS:
		QRF(preader->ext_push.p_bytes(TAG_EMBOSS_END, sizeof(TAG_EMBOSS_END) - 1));
		return true;
	case ATTR_ENGRAVE: 
		QRF(preader->ext_push.p_bytes(TAG_ENGRAVE_END, sizeof(TAG_ENGRAVE_END) - 1));
		return true;
	case ATTR_EXPAND: 
		QRF(preader->ext_push.p_bytes(TAG_EXPAND_END, sizeof(TAG_EXPAND_END) - 1));
		return true;
	case ATTR_CAPS:
		preader->b_simulate_allcaps = false;
		return true;
	case ATTR_SMALLCAPS: 
		QRF(preader->ext_push.p_bytes(TAG_SMALLER_END, sizeof(TAG_SMALLER_END) - 1));
		preader->b_simulate_smallcaps = false;
		return true;
	case ATTR_UBYTES:
		preader->b_ubytes_switch = false;
		return true;
	case ATTR_PICT:
		preader->is_within_picture = false;
		return true;
	}
	return true;
}

static bool rtf_attrstack_express_all(RTF_READER *preader)
{
	int i;
	DOUBLE_LIST_NODE *pnode;
	ATTRSTACK_NODE *pattrstack;
	
	pnode = double_list_get_tail(&preader->attr_stack_list);
	if (NULL == pnode) {
		debug_info("[rtf]: no stack to express all attribute from");
		return true;
	}
	pattrstack = (ATTRSTACK_NODE*)pnode->pdata;
	for (i=0; i<= pattrstack->tos; i++) { 
		if (!rtf_express_attr_begin(preader, pattrstack->attr_stack[i],
		    pattrstack->attr_params[i]))
			return false;
	}
	return true;
}

static bool rtf_attrstack_push_express(RTF_READER *preader, int attr, int param)
{
	DOUBLE_LIST_NODE *pnode;
	ATTRSTACK_NODE *pattrstack;
	
	pnode = double_list_get_tail(&preader->attr_stack_list);
	if (NULL == pnode) {
		debug_info("[rtf]: cannot find stack node for pushing attribute");
		return false;
	}
	pattrstack = (ATTRSTACK_NODE*)pnode->pdata;
	if (pattrstack->tos >= MAX_ATTRS - 1) {
		debug_info("[rtf]: too many attributes");
		return false;
	}
	if (!rtf_starting_body(preader) || !rtf_starting_text(preader))
		return false;
	pattrstack->tos ++;
	pattrstack->attr_stack[pattrstack->tos] = attr;
	pattrstack->attr_params[pattrstack->tos] = param;
	return rtf_express_attr_begin(preader, attr, param);
}

static bool rtf_stack_list_new_node(RTF_READER *preader)
{
	auto pattrstack = me_alloc<ATTRSTACK_NODE>();
	if (NULL == pattrstack) {
		return false;
	}
	memset(pattrstack, 0, sizeof(ATTRSTACK_NODE));
	pattrstack->node.pdata = pattrstack;
	pattrstack->tos = -1;
	double_list_append_as_tail(
		&preader->attr_stack_list,
		&pattrstack->node);
	return true;
}

static bool rtf_attrstack_pop_express(RTF_READER *preader, int attr)
{
	DOUBLE_LIST_NODE *pnode;
	ATTRSTACK_NODE *pattrstack;
	
	pnode = double_list_get_tail(&preader->attr_stack_list);
	if (NULL == pnode) {
		return true;
	}
	pattrstack = (ATTRSTACK_NODE*)pnode->pdata;
	if (pattrstack->tos >= 0 &&
		pattrstack->attr_stack[pattrstack->tos] == attr) {
		if (!rtf_express_attr_end(preader, attr,
		    pattrstack->attr_params[pattrstack->tos]))
			return false;
		pattrstack->tos --;
		return true;
	}
	return true;
}

static int rtf_attrstack_peek(RTF_READER *preader)
{
	DOUBLE_LIST_NODE *pnode;
	ATTRSTACK_NODE *pattrstack;
	
	pnode = double_list_get_tail(&preader->attr_stack_list);
	if (NULL == pnode) {
		debug_info("[rtf]: cannot find stack node for peeking attribute");
		return ATTR_NONE;
	}
	pattrstack = (ATTRSTACK_NODE*)pnode->pdata;
	if(pattrstack->tos >= 0) {
		return pattrstack->attr_stack[pattrstack->tos];
	}
	return ATTR_NONE;
}

static void rtf_stack_list_free_node(RTF_READER *preader) 
{
	auto pnode = double_list_pop_back(&preader->attr_stack_list);
	if (NULL != pnode) {
		free(pnode->pdata);
	}
}

static bool rtf_attrstack_pop_express_all(RTF_READER *preader)
{
	DOUBLE_LIST_NODE *pnode;
	ATTRSTACK_NODE *pattrstack;
	
	pnode = double_list_get_tail(&preader->attr_stack_list);
	if (NULL != pnode) {
		pattrstack = (ATTRSTACK_NODE*)pnode->pdata;
		for (; pattrstack->tos>=0; pattrstack->tos--) {
			if (!rtf_express_attr_end(preader,
			    pattrstack->attr_stack[pattrstack->tos],
			    pattrstack->attr_params[pattrstack->tos]))
				return false;
		}
	}
	return true;
}

static bool rtf_attrstack_find_pop_express(RTF_READER *preader, int attr)
{
	int i;
	DOUBLE_LIST_NODE *pnode;
	ATTRSTACK_NODE *pattrstack;
	
	pnode = double_list_get_tail(&preader->attr_stack_list);
	if (NULL == pnode) {
		debug_info("[rtf]: cannot find stack node for finding attribute");
		return true;
	}
	pattrstack = (ATTRSTACK_NODE*)pnode->pdata;
	bool b_found = false;
	for (i=0; i<=pattrstack->tos; i++) {
		if (pattrstack->attr_stack[i] == attr) {
			b_found = true;
			break;
		}
	}
	if (!b_found) {
		debug_info("[rtf]: cannot find attribute in stack node");
		return true;
	}
	for (i=pattrstack->tos; i>=0; i--) {
		if (!rtf_express_attr_end(preader, pattrstack->attr_stack[i],
		    pattrstack->attr_params[i]))
			return false;
		if (pattrstack->attr_stack[i] == attr) {
			memmove(pattrstack->attr_stack + i,
				pattrstack->attr_stack + i + 1,
				pattrstack->tos - i);
			memmove(pattrstack->attr_params + i,
				pattrstack->attr_params + i + 1,
				sizeof(char*)*(pattrstack->tos - i));
			pattrstack->tos --;
			break;
		}
	}
	for (; i<=pattrstack->tos; i++) {
		if (!rtf_express_attr_begin(preader, pattrstack->attr_stack[i],
		    pattrstack->attr_params[i]))
			return false;
	}
	return true;
}

static void rtf_ungetchar(RTF_READER *preader, int ch)
{
	if (preader->ungot_chars[0] >= 0 &&
		preader->ungot_chars[1] >= 0 &&
		preader->ungot_chars[2] >= 0) {
		debug_info("[rtf]: more than 3 ungot chars");
	}
	preader->ungot_chars[2] = preader->ungot_chars[1];
	preader->ungot_chars[1] = preader->ungot_chars[0];
	preader->ungot_chars[0] = ch;
}

static int rtf_getchar(RTF_READER *preader, int *pch)
{
	int ch;
	int status;
	int8_t tmp_char;

	if (preader->ungot_chars[0] >= 0) {
		ch = preader->ungot_chars[0]; 
		preader->ungot_chars[0] = preader->ungot_chars[1]; 
		preader->ungot_chars[1] = preader->ungot_chars[2];
		preader->ungot_chars[2] = -1;
		preader->last_returned_ch = ch;
		*pch = ch;
		return EXT_ERR_SUCCESS;
	}
	do {
		status = preader->ext_pull.g_int8(&tmp_char);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		ch = tmp_char;
		if ('\n' == ch) {
			/* Convert \(newline) into \par here */
			if ('\\' == preader->last_returned_ch) {
				rtf_ungetchar(preader, ' ');
				rtf_ungetchar(preader, 'r');
				rtf_ungetchar(preader, 'a');
				ch = 'p';
				break;
			}
		}
	} 
	while ('\r' == ch);
	if ('\t' == ch) {
		ch = ' ';
	}
	preader->last_returned_ch = ch;
	*pch = ch;
	return EXT_ERR_SUCCESS;
}

static char* rtf_read_element(RTF_READER *preader) 
{
	int ch, ch2;
	unsigned int ix;
	bool need_unget = false, have_whitespace = false;
	bool is_control_word = false, b_numeric_param = false;
	unsigned int current_max_length;
	
	
	ix = 0;
	current_max_length = 10;
	auto input_str = static_cast<char *>(calloc(1, current_max_length));
	if (NULL == input_str) {
		debug_info("[rtf]: cannot allocate word storage");
		return NULL;
	}
	
	do {
		if (EXT_ERR_SUCCESS != rtf_getchar(preader, &ch)) {
			free(input_str);
			debug_info("[rtf]: fail to get char from reader");
			return NULL;
		}
	} while ('\n' == ch);
	
	if (' ' == ch) {
		/* trm multiple space chars into one */
		while (' ' == ch) {
			if (EXT_ERR_SUCCESS != rtf_getchar(preader, &ch)) {
				free(input_str);
				debug_info("[rtf]: fail to get char from reader");
				return NULL;
			}
			have_whitespace = true;
		}
		if (have_whitespace) {
			rtf_ungetchar(preader, ch);
			input_str[0] = ' '; 
			input_str[1] = 0;
			return input_str;
		}
	}

	switch (ch) {
	case '\\':
		if (EXT_ERR_SUCCESS != rtf_getchar(preader, &ch2)) {
			free(input_str);
			debug_info("[rtf]: fail to get char from reader");
			return NULL;
		}
		/* look for two-character command words */
		switch (ch2) {
		case '\n':
			strcpy (input_str, "\\par");
			return input_str;
		case '~':
		case '{':
		case '}':
		case '\\':
		case '_':
		case '-':
			input_str[0] = '\\';
			input_str[1] = ch2;
			input_str[2] = '\0';
			return input_str;
		case '\'':
			/* preserve \'## expressions (hex char exprs) for later */
			input_str[0]='\\'; 
			input_str[1]='\'';
			if (EXT_ERR_SUCCESS != rtf_getchar(preader, &ch)) {
				free(input_str);
				debug_info("[rtf]: fail to get char from reader");
				return nullptr;
			}
			input_str[2] = ch;
			if (EXT_ERR_SUCCESS != rtf_getchar(preader, &ch)) {
				free(input_str);
				debug_info("[rtf]: fail to get char from reader");
				return NULL;
			}
			input_str[3] = ch;
			input_str[4] = '\0';
			return input_str;
		}
		is_control_word = true;
		ix = 1;
		input_str[0] = ch;
		ch = ch2;
		break;
	case '\t':
		/* in rtf, a tab char is the same as \tab */
		strcpy (input_str, "\\tab");
		return input_str;
	case '{':
	case '}':
	case ';':
		input_str[0]=ch; 
		input_str[1]=0;
		return input_str;
	}

	while (true) {
		if ('\t' == ch || '{' == ch || '}' == ch || '\\' == ch) {
			need_unget = true;
			break;
		}
		if ('\n' == ch) { 
			if (is_control_word)
				break;
			if (EXT_ERR_SUCCESS != rtf_getchar(preader, &ch)) {
				free(input_str);
				debug_info("[rtf]: fail to get char from reader");
				return NULL;
			}
			continue; 
		}
		if (';' == ch) {
			if (is_control_word) {
				need_unget = true;
				break;
			}
		}
		if (' ' == ch) {
			if (!is_control_word)
				need_unget = true;
			break;
		}
		if (is_control_word) {
			if (!b_numeric_param && (HX_isdigit(ch) || ch == '-')) {
				b_numeric_param = true;
			} else {
				if (b_numeric_param && !HX_isdigit(ch)) {
					if (ch != ' ') {
						need_unget = true;
					}
					break;
				}
			}
		}
		
		input_str[ix] = ch;
		ix ++;
		if (ix == current_max_length) {
			current_max_length *= 2;
			auto input_new = re_alloc<char>(input_str, current_max_length);
			if (NULL == input_new) {
				free(input_str);
				debug_info("[rtf]: out of memory");
				return NULL;
			}
			input_str = input_new;
		}
		if (EXT_ERR_SUCCESS != rtf_getchar(preader, &ch)) {
			free(input_str);
			debug_info("[rtf]: fail to get char from reader");
			return NULL;
		}
	}
	if (need_unget)
		rtf_ungetchar(preader, ch);
	input_str[ix] = '\0';
	if (strncmp(input_str, "\\bin", 4) == 0 && HX_isdigit(input_str[4]))
		preader->ext_pull.advance(strtol(input_str + 4, nullptr, 0));
	return input_str;
}

static bool rtf_optimize_element(DOUBLE_LIST *pcollection_list,
    const char *str_word)
{
	const char *text;
	static constexpr char opt_tags[][4] = {"\\fs", "\\f"};
	
	for (size_t i = 0; i < GX_ARRAY_SIZE(opt_tags); ++i) {
		auto len = strlen(opt_tags[i]);
		if (0 == strncmp(opt_tags[i], str_word, len) &&
		    (HX_isdigit(str_word[len]) || str_word[len] == '-')) {
			text = rtf_get_from_collection(pcollection_list, i);
			if (NULL == text) {
				continue;
			}
			if (strcmp(text, str_word) == 0)
				return true;
			rtf_add_to_collection(pcollection_list, i, str_word);
			break;
		}
	}
	return false;
}

static bool rtf_load_element_tree(RTF_READER *preader)
{
	char *input_word;
	GROUP_NODE *pgroup;
	SIMPLE_TREE_NODE *pword;
	GROUP_NODE *plast_group;
	SIMPLE_TREE_NODE *plast_node;
	
	plast_group = NULL;
	plast_node = NULL;
	while ((input_word = rtf_read_element(preader)) != NULL) {
		if (input_word[0] == '{') {
			free(input_word);
			pgroup = me_alloc<GROUP_NODE>();
			if (NULL == pgroup) {
				debug_info("[rtf]: out of memory");
				return false;
			}
			pgroup->node.pdata = NULL;
			double_list_init(&pgroup->collection_list);
			if (NULL == plast_group) {
				preader->element_tree.set_root(&pgroup->node);
			} else if (plast_node != nullptr) {
				preader->element_tree.insert_sibling(
					plast_node, &pgroup->node,
					SIMPLE_TREE_INSERT_AFTER);
			} else {
				preader->element_tree.add_child(
					&plast_group->node,
					&pgroup->node, SIMPLE_TREE_ADD_LAST);
			}
			plast_group = pgroup;
			plast_node = NULL;
		} else if (input_word[0] == '}') {
			free(input_word);
			if (NULL == plast_group) {
				debug_info("[rtf]: rtf format error, missing first '{'");
				return false;
			}
			rtf_free_collection(&plast_group->collection_list);
			plast_node = &plast_group->node;
			plast_group = containerof(plast_group->node.get_parent(), GROUP_NODE, node);
			if (NULL == plast_group) {
				return true;
			}
		} else {
			if (NULL == plast_group) {
				free(input_word);
				debug_info("[rtf]: rtf format error, missing first '{'");
				return false;
			}
			if (rtf_optimize_element(&plast_group->collection_list, input_word)) {
				free(input_word);
				return true;
			}
			pword = me_alloc<SIMPLE_TREE_NODE>();
			if (NULL == pword) {
				free(input_word);
				debug_info("[rtf]: out of memory");
				return false;
			}
			pword->pdata = input_word;
			if (NULL == plast_node) {
				preader->element_tree.add_child(
					&plast_group->node, pword,
					SIMPLE_TREE_ADD_LAST);
			} else {
				preader->element_tree.insert_sibling(plast_node,
					pword, SIMPLE_TREE_INSERT_AFTER);
			}
			plast_node = pword;
		}
	}
	/* incomplete RTF... pretend it's ok */
	return true;
}

static bool rtf_starting_body(RTF_READER *preader)
{
	if (preader->have_printed_body)
		return true;
	preader->is_within_header = false;
	preader->have_printed_body = true;
	if (preader->have_fromhtml)
		return true;
	QRF(preader->ext_push.p_bytes(TAG_HEADER_END, sizeof(TAG_HEADER_END) - 1));
	QRF(preader->ext_push.p_bytes(TAG_BODY_BEGIN, sizeof(TAG_BODY_BEGIN) - 1));
	return true;
}

static bool rtf_starting_text(RTF_READER *preader)
{
	if (!preader->is_within_table)
		return true;
	if (!preader->b_printed_row_begin) {
		QRF(preader->ext_push.p_bytes(TAG_TABLE_ROW_BEGIN, sizeof(TAG_TABLE_ROW_BEGIN) - 1));
		preader->b_printed_row_begin = true;
		preader->b_printed_row_end = false;
		preader->b_printed_cell_begin = false;
	}
	if (!preader->b_printed_cell_begin) {
		QRF(preader->ext_push.p_bytes(TAG_TABLE_CELL_BEGIN, sizeof(TAG_TABLE_CELL_BEGIN) - 1));
		if (!rtf_attrstack_express_all(preader))
			return false;
		preader->b_printed_cell_begin = true;
		preader->b_printed_cell_end = false;
	}
	return true;
}

static bool rtf_starting_paragraph_align(RTF_READER *preader, int align)
{
	if (preader->is_within_header && align != ALIGN_LEFT) {
		if (!rtf_starting_body(preader))
			return false;
	}
	switch (align) {
	case ALIGN_CENTER:
		QRF(preader->ext_push.p_bytes(TAG_CENTER_BEGIN, sizeof(TAG_CENTER_BEGIN) - 1));
		break;
	case ALIGN_LEFT:
		break;
	case ALIGN_RIGHT:
		QRF(preader->ext_push.p_bytes(TAG_ALIGN_RIGHT_BEGIN, sizeof(TAG_ALIGN_RIGHT_BEGIN) - 1));
		break;
	case ALIGN_JUSTIFY:
		QRF(preader->ext_push.p_bytes(TAG_JUSTIFY_BEGIN, sizeof(TAG_JUSTIFY_BEGIN) - 1));
		break;
	}
	return true;
}

static bool rtf_ending_paragraph_align(RTF_READER *preader, int align)
{
	switch (align) {
	case ALIGN_CENTER:
		QRF(preader->ext_push.p_bytes(TAG_CENTER_END, sizeof(TAG_CENTER_END) - 1));
		break;
	case ALIGN_LEFT:
		break;
	case ALIGN_RIGHT:
		QRF(preader->ext_push.p_bytes(TAG_ALIGN_RIGHT_END, sizeof(TAG_ALIGN_RIGHT_END) - 1));
		break;
	case ALIGN_JUSTIFY:
		QRF(preader->ext_push.p_bytes(TAG_JUSTIFY_END, sizeof(TAG_JUSTIFY_END) - 1));
		break;
	}
	return true;
}

static bool rtf_begin_table(RTF_READER *preader)
{
	preader->is_within_table = true;
	preader->b_printed_row_begin = false;
	preader->b_printed_cell_begin = false;
	preader->b_printed_row_end = false;
	preader->b_printed_cell_end = false;
	if (!rtf_stack_list_new_node(preader) || !rtf_starting_body(preader))
		return false;
	QRF(preader->ext_push.p_bytes(TAG_TABLE_BEGIN, sizeof(TAG_TABLE_BEGIN) - 1));
	return true;
}

static bool rtf_end_table(RTF_READER *preader)
{
	if (!preader->is_within_table)
		return true;
	if (!preader->b_printed_cell_end) {
		if (!rtf_attrstack_pop_express_all(preader))
			return false;
		QRF(preader->ext_push.p_bytes(TAG_TABLE_CELL_END, sizeof(TAG_TABLE_CELL_END) - 1));
	}
	if (!preader->b_printed_row_end) {
		QRF(preader->ext_push.p_bytes(TAG_TABLE_ROW_END, sizeof(TAG_TABLE_ROW_END) - 1));
	}
	QRF(preader->ext_push.p_bytes(TAG_TABLE_END, sizeof(TAG_TABLE_END) - 1));
	preader->is_within_table = false;
	preader->b_printed_row_begin = false;
	preader->b_printed_cell_begin = false;
	preader->b_printed_row_end = false;
	preader->b_printed_cell_end = false;
	return true;
}

static bool rtf_check_for_table(RTF_READER *preader)
{
	if (preader->coming_pars_tabular == 0 && preader->is_within_table)
		return rtf_end_table(preader);
	else if (preader->coming_pars_tabular != 0 && !preader->is_within_table)
		return rtf_begin_table(preader);
	return true;
}

static bool rtf_put_iconv_cache(RTF_READER *preader, int ch)
{
	if (preader->b_ubytes_switch) {
		if (preader->ubytes_left > 0) {
			preader->ubytes_left --;
			return true;
		}
	}
	QRF(preader->iconv_push.p_uint8(ch));
	return true;
}

static bool rtf_build_font_table(RTF_READER *preader, SIMPLE_TREE_NODE *pword)
{
	int ret;
	int num;
	int cpid;
	int param;
	char *ptoken;
	char *string;
	int tmp_cpid;
	int fcharsetcp;
	char name[1024];
	FONTENTRY tmp_entry;
	char tmp_buff[1024];
	char tmp_name[MAX_CONTROL_LEN];
	
	do {
		auto pword2 = pword->get_child();
		if (NULL == pword2) {
			continue;
		}
		if (NULL == pword2->pdata) {
			return true;
		}
		do {
			if (rtf_parse_control(static_cast<char *>(pword2->pdata) + 1,
				tmp_name, MAX_CONTROL_LEN, &num) > 0
				&& 0 == strcmp(tmp_name, "f")) {
				break;
			}
		} while ((pword2 = pword2->get_sibling()) != nullptr);
		if (NULL == pword2) {
			continue;
		}
		if (num < 0) {
			debug_info("[rtf]: illegal font id in font table");
			return false;
		}
		tmp_buff[0] = '\0';
		cpid = -1;
		fcharsetcp = -1;
		size_t tmp_offset = 0;
		while ((pword2 = pword2->get_sibling()) != nullptr) {
			if (NULL == pword2->pdata) {
				continue;
			}
			string = static_cast<char *>(pword2->pdata);
			if ('\\' != string[0]) {
				auto tmp_len = strlen(string);
				if (tmp_len + tmp_offset > sizeof(tmp_buff) - 1) {
					debug_info("[rtf]: invalid font name");
					return false;
				} else {
					memcpy(tmp_buff + tmp_offset, string, tmp_len);
					tmp_offset += tmp_len;
				}
				continue;
			} else if (string[1] == '\'' && string[2] != '\0' && string[3] != '\0') {
				if (tmp_offset + 1 > sizeof(tmp_buff) - 1) {
					debug_info("[rtf]: invalid font name");
					return false;
				}
				tmp_buff[tmp_offset] = rtf_decode_hex_char(string + 2);
				tmp_offset ++;
				continue;
			}
			ret = rtf_parse_control(string + 1,
			      tmp_name, MAX_CONTROL_LEN, &param);
			if (ret < 0) {
				debug_info("[rtf]: illegal control word in font table");
				continue;
			} else if (ret == 0) {
				continue;
			}
			/* ret > 0 */
			if (0 == strcmp(tmp_name, "u")) {
				wchar_to_utf8(param, tmp_name);
				if (-1 != cpid) {
					tmp_cpid = cpid;
				} else if (-1 != fcharsetcp) {
					tmp_cpid = fcharsetcp;
				} else {
					tmp_cpid = 1252;
				}
				if (!string_from_utf8(rtf_cpid_to_encoding(tmp_cpid),
				    tmp_name, name, arsizeof(name))) {
					debug_info("[rtf]: invalid font name");
					return false;
				} else {
					auto tmp_len = strlen(name);
					if (tmp_len + tmp_offset >
					    sizeof(tmp_buff) - 1) {
						debug_info("[rtf]: invalid font name");
						return false;
					}
					memcpy(tmp_buff + tmp_offset, name, tmp_len);
					tmp_offset += tmp_len;
				}
			} else if (0 == strcmp(tmp_name, "fcharset")) {
				fcharsetcp = rtf_fcharset_to_cpid(param);
			} else if (0 == strcmp(tmp_name, "cpg")) {
				cpid = param;
			}
		}
		if (0 == tmp_offset) {
			debug_info("[rtf]: invalid font name");
			return false;
		}
		tmp_buff[tmp_offset] = '\0';
		if (-1 == cpid) {
			cpid = fcharsetcp;
		}
		if (cpid != -1)
			strcpy(tmp_entry.encoding, rtf_cpid_to_encoding(cpid));
		else if (strcasestr(name, "symbol") != nullptr)
			tmp_entry.encoding[0] = '\0';
		else
			strcpy(tmp_entry.encoding, "windows-1252");
		if (-1 == cpid) {
			cpid = 1252;
		}
		if (!string_to_utf8(rtf_cpid_to_encoding(cpid), tmp_buff, name)) {
			debug_info("[rtf]: invalid font name");
			strcpy(name, DEFAULT_FONT_STR);
		}
		ptoken = strchr(name, ';');
		if (NULL != ptoken) {
			*ptoken = '\0';
		}
		gx_strlcpy(tmp_entry.name, name, GX_ARRAY_SIZE(tmp_entry.name));
		preader->pfont_hash->add(num, &tmp_entry);
	} while ((pword = pword->get_sibling()) != nullptr);
	if ('\0' == preader->default_encoding[0]) {
		strcpy(preader->default_encoding, "windows-1252");
	}
	if (!preader->have_ansicpg) {
		const FONTENTRY *pentry = rtf_lookup_font(preader, preader->default_font_number);
		if (NULL != pentry) {
			strcpy(preader->default_encoding, pentry->encoding);
		} else {
			strcpy(preader->default_encoding, "windows-1252");
		}
	}
	return true;
}

static bool rtf_word_output_date(RTF_READER *preader, SIMPLE_TREE_NODE *pword)
{
	int day;
	int hour;
	int year;
	int month;
	int minute;
	int tmp_len;
	char *string;
	char tmp_buff[32];
	
	day = 0;
	hour = -1;
	year = 0;
	month = 0;
	minute = -1;
	do {
	 	if (NULL == pword->pdata) {
			return false;
		}
		string = static_cast<char *>(pword->pdata);
		if ('\\' == *string) {
			string ++;
			if (0 == strncmp(string, "yr", 2)
			    && HX_isdigit(string[2])) {
				year = strtol(string + 2, nullptr, 0);
			} else if (0 == strncmp(string, "mo", 2)
			    && HX_isdigit(string[2])) {
				month = strtol(string + 2, nullptr, 0);
			} else if (0 == strncmp(string, "dy", 2)
			    && HX_isdigit(string[2])) {
				day = strtol(string + 2, nullptr, 0);
			} else if (0 == strncmp(string, "min", 3)
			    && HX_isdigit(string[3])) {
				minute = strtol(string + 3, nullptr, 0);
			} else if (0 == strncmp(string, "hr", 2)
			    && HX_isdigit(string[2])) {
				hour = strtol(string + 2, nullptr, 0);
			}
		}
	} while ((pword = pword->get_sibling()) != nullptr);
	tmp_len = snprintf(tmp_buff, arsizeof(tmp_buff), "%04d-%02d-%02d ", year, month, day);
	if (hour >= 0 && minute >= 0) {
		tmp_len += sprintf(tmp_buff + tmp_len, "%02d:%02d ", hour, minute);
	}
	QRF(preader->ext_push.p_bytes(tmp_buff, tmp_len));
	return true;
}

static bool rtf_process_info_group(RTF_READER *preader, SIMPLE_TREE_NODE *pword)
{
	int ch;

	for (; pword != nullptr; pword = pword->get_sibling()) {
		auto pchild = pword->get_child();
		if (pchild == nullptr)
			continue;
		if (NULL == pchild->pdata) {
			return true;
		}
		if (strcmp(static_cast<char *>(pchild->pdata), "\\title") == 0) {
			QRF(preader->ext_push.p_bytes(TAG_DOCUMENT_TITLE_BEGIN, sizeof(TAG_DOCUMENT_TITLE_BEGIN) - 1));
			for (auto pword2 = pchild->get_sibling();
			     pword2 != nullptr; pword2 = pword2->get_sibling()) {
				if (pword2->pdata == nullptr)
					continue;
				if ('\\' != ((char *)pword2->pdata)[0]) {
					if (!rtf_flush_iconv_cache(preader))
						return false;
					if (!rtf_escape_output(preader, static_cast<char *>(pword2->pdata)))
						return false;
				} else if ('\'' == ((char *)pword2->pdata)[1]) {
					ch = rtf_decode_hex_char(static_cast<char *>(pword2->pdata) + 2);
					QRF(preader->iconv_push.p_uint8(ch));
				}
			}
			if (!rtf_flush_iconv_cache(preader))
				return false;
			QRF(preader->ext_push.p_bytes(TAG_DOCUMENT_TITLE_END, sizeof(TAG_DOCUMENT_TITLE_END) - 1));
		} else if (strcmp(static_cast<char *>(pchild->pdata), "\\author") == 0) {
			QRF(preader->ext_push.p_bytes(TAG_DOCUMENT_AUTHOR_BEGIN, sizeof(TAG_DOCUMENT_AUTHOR_BEGIN) - 1));
			for (auto pword2 = pchild->get_sibling();
			     pword2 != nullptr; pword2 = pword2->get_sibling()) {
				if (pword2->pdata == nullptr)
					continue;
				if ('\\' != ((char *)pword2->pdata)[0]) {
					if (!rtf_flush_iconv_cache(preader))
						return false;
					if (!rtf_escape_output(preader, static_cast<char *>(pword2->pdata)))
						return false;
				} else if ('\'' == ((char *)pword2->pdata)[1]) {
					ch = rtf_decode_hex_char(static_cast<char *>(pword2->pdata) + 2);
					QRF(preader->iconv_push.p_uint8(ch));
				}
			}
			if (!rtf_flush_iconv_cache(preader))
				return false;
			QRF(preader->ext_push.p_bytes(TAG_DOCUMENT_AUTHOR_END, sizeof(TAG_DOCUMENT_AUTHOR_END) - 1));
		} else if (strcmp(static_cast<char *>(pchild->pdata), "\\creatim") == 0) {
			QRF(preader->ext_push.p_bytes(TAG_COMMENT_BEGIN, sizeof(TAG_COMMENT_BEGIN) - 1));
			QRF(preader->ext_push.p_bytes("creation date: ", 15));
			if (pchild->get_sibling() != nullptr &&
			    !rtf_word_output_date(preader, pchild->get_sibling()))
				return false;
			QRF(preader->ext_push.p_bytes(TAG_COMMENT_END, sizeof(TAG_COMMENT_END) - 1));
		} else if (strcmp(static_cast<char *>(pchild->pdata), "\\printim") == 0) {
			QRF(preader->ext_push.p_bytes(TAG_COMMENT_BEGIN, sizeof(TAG_COMMENT_BEGIN) - 1));
			QRF(preader->ext_push.p_bytes("last print date: ", 17));
			if (pchild->get_sibling() != nullptr &&
			    !rtf_word_output_date(preader, pchild->get_sibling()))
				return false;
			QRF(preader->ext_push.p_bytes(TAG_COMMENT_END, sizeof(TAG_COMMENT_END) - 1));
		} else if (strcmp(static_cast<char *>(pchild->pdata), "\\buptim") == 0) {
			QRF(preader->ext_push.p_bytes(TAG_COMMENT_BEGIN, sizeof(TAG_COMMENT_BEGIN) - 1));
			QRF(preader->ext_push.p_bytes("last backup date: ", 18));
			if (pchild->get_sibling() != nullptr &&
			    !rtf_word_output_date(preader, pchild->get_sibling()))
					return false;
			QRF(preader->ext_push.p_bytes(TAG_COMMENT_END, sizeof(TAG_COMMENT_END) - 1));
		} else if (strcmp(static_cast<char *>(pchild->pdata), "\\revtim") == 0) {
			QRF(preader->ext_push.p_bytes(TAG_COMMENT_BEGIN, sizeof(TAG_COMMENT_BEGIN) - 1));
			QRF(preader->ext_push.p_bytes("modified date: ", 15));
			if (pchild->get_sibling() != nullptr &&
			    !rtf_word_output_date(preader, pchild->get_sibling()))
				return false;
			QRF(preader->ext_push.p_bytes(TAG_COMMENT_END, sizeof(TAG_COMMENT_END) - 1));
		}
	}
	return true;
}


static void rtf_process_color_table(
	RTF_READER *preader, SIMPLE_TREE_NODE *pword)
{
	int r;
	int g;
	int b;
	
	r = 0;
	g = 0;
	b = 0;
	do {
		if (NULL == pword->pdata || preader->total_colors >= MAX_COLORS) {
			break;
		}
		if (strncmp("\\red", static_cast<char *>(pword->pdata), 4) == 0) {
			r = strtol(static_cast<char *>(pword->pdata) + 4, nullptr, 0);
			while (r > 255) {
				r >>= 8;
			}
		} else if (strncmp("\\green", static_cast<char *>(pword->pdata), 6) == 0) {
			g = strtol(static_cast<char *>(pword->pdata) + 6, nullptr, 0);
			while (g > 255) {
				g >>= 8;
			}
		} else if (strncmp("\\blue", static_cast<char *>(pword->pdata), 5) == 0) {
			b = strtol(static_cast<char *>(pword->pdata) + 5, nullptr, 0);
			while (b > 255) {
				b >>= 8;
			}
		} else {
			if (strcmp(static_cast<char *>(pword->pdata), ";") == 0) {
				preader->color_table[preader->total_colors] =
									(r << 16) | (g << 8) | b;
				preader->total_colors ++;
				if (preader->total_colors >= MAX_COLORS) {
					return;
				}
				r = 0;
				g = 0;
				b = 0;
			}
		}
	} while ((pword = pword->get_sibling()) != nullptr);
}

static int rtf_cmd_rtf(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_fromhtml(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_cf(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (!have_param || num < 0 || num >= preader->total_colors) {
		debug_info("[rtf]: font color change attempted is invalid");
	} else {
		if (!rtf_attrstack_push_express(preader, ATTR_FOREGROUND,
		    preader->color_table[num]))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_cb(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (!have_param || num < 0 || num >= preader->total_colors) {
		debug_info("[rtf]: font color change attempted is invalid");
	} else {
		if (!rtf_attrstack_push_express(preader, ATTR_BACKGROUND,
		    preader->color_table[num]))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_fs(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (!have_param)
		return CMD_RESULT_CONTINUE;
	num /= 2;
	if (!rtf_attrstack_push_express(preader, ATTR_FONTSIZE, num))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_field(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	int tmp_len;
	char tmp_buff[1024];
	bool b_endnotecitations = false;
	
	do {
		auto pchild = pword->get_child();
		if (NULL == pchild) {
			continue;
		}
		if (NULL == pchild->pdata) {
			return CMD_RESULT_IGNORE_REST;
		}
		if (strcmp(static_cast<char *>(pchild->pdata), "\\fldrslt") == 0)
			return CMD_RESULT_CONTINUE;
		if (strcmp(static_cast<char *>(pchild->pdata), "\\*") != 0)
			continue;
		for (auto pword2 = pchild->get_sibling(); pword2 != nullptr;
		     pword2 = pword2->get_sibling()) {
			if (pword2->pdata == nullptr ||
			    strcmp(static_cast<char *>(pword2->pdata), "\\fldinst") != 0)
				continue;
			auto pword3 = pword2->get_sibling();
			if (pword3 != nullptr && pword3->pdata != nullptr &&
			    strcmp(static_cast<char *>(pword3->pdata), "SYMBOL") == 0) {
				auto pword4 = pword3->get_sibling();
				while (pword4 != nullptr && pword4->pdata != nullptr &&
				    strcmp(static_cast<char *>(pword4->pdata), " ") == 0)
					pword4 = pword4->get_sibling();
				if (NULL != pword4 && NULL != pword4->pdata) {
					int ch = strtol(static_cast<char *>(pword4->pdata), nullptr, 0);
					if (!rtf_attrstack_push_express(preader,
					    ATTR_FONTFACE, -7))
						return CMD_RESULT_ERROR;
					tmp_len = snprintf(tmp_buff, arsizeof(tmp_buff), TAG_UNISYMBOL_PRINT, ch);
					if (preader->ext_push.p_bytes(tmp_buff, tmp_len) != EXT_ERR_SUCCESS)
						return CMD_RESULT_ERROR;
				}
			}
			for (; pword3 != nullptr; pword3 = pword3->get_sibling())
				if (pword3->get_child() != nullptr)
					break;
			if (NULL != pword3) {
				pword3 = pword3->get_child();
			}
			for (; pword3 != nullptr; pword3 = pword3->get_sibling()) {
				if (NULL == pword3->pdata) {
					return CMD_RESULT_CONTINUE;
				}
				if (strcmp(static_cast<char *>(pword3->pdata), "EN.CITE") == 0) {
					b_endnotecitations = true;
					continue;
				} else if (strcmp(static_cast<char *>(pword3->pdata), "HYPERLINK") != 0) {
					continue;
				}
				if (b_endnotecitations)
					continue;
				auto pword4 = pword3->get_sibling();
				while (pword4 != nullptr && pword4->pdata != nullptr &&
				    strcmp(static_cast<char *>(pword4->pdata), " ") == 0)
					pword4 = pword4->get_sibling();
				if (NULL != pword4 && NULL != pword4->pdata) {
					tmp_len = gx_snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff),
						  TAG_HYPERLINK_BEGIN, static_cast<const char *>(pword4->pdata));
					if (preader->ext_push.p_bytes(tmp_buff, tmp_len) != EXT_ERR_SUCCESS)
						return CMD_RESULT_ERROR;
					return CMD_RESULT_HYPERLINKED;
				}
			}
		}
	} while ((pword = pword->get_sibling()) != nullptr);
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_f(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (!have_param)
		return CMD_RESULT_CONTINUE;
	const FONTENTRY *pentry = rtf_lookup_font(preader, num);
	if (pentry == nullptr || strcasestr(pentry->name, "symbol") != nullptr)
		return CMD_RESULT_CONTINUE;
	if (!rtf_attrstack_push_express(preader, ATTR_FONTFACE, num))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_deff(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param)
		preader->default_font_number = num;
    return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_highlight(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!have_param || num < 0 || num >= preader->total_colors) {
		debug_info("[rtf]: font background "
			"color change attempted is invalid");
	} else {
		if (!rtf_attrstack_push_express(preader, ATTR_BACKGROUND,
		    preader->color_table[num]))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_tab(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	int need;
	
	if (preader->have_fromhtml) {
		if (preader->ext_push.p_uint8(0x09) != EXT_ERR_SUCCESS)
			return CMD_RESULT_ERROR;
		++preader->total_chars_in_line;
		return CMD_RESULT_CONTINUE;
	}
	need = 8 - preader->total_chars_in_line % 8;
	preader->total_chars_in_line += need;
	while (need > 0) {
		if (preader->ext_push.p_bytes(TAG_FORCED_SPACE,
		    sizeof(TAG_FORCED_SPACE) - 1) != EXT_ERR_SUCCESS)
			return CMD_RESULT_ERROR;
		need--;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_plain(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!rtf_attrstack_pop_express_all(preader))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_fnil(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_FONTFACE, -1))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_froman(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_FONTFACE, -2))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_fswiss(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_FONTFACE, -3))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_fmodern(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_FONTFACE, -4))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_fscript(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_FONTFACE, -5))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_fdecor(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_FONTFACE, -6))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_ftech(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_FONTFACE, -7))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_expand(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param) {
		if (0 == num) {
			if (!rtf_attrstack_pop_express(preader, ATTR_EXPAND))
				return CMD_RESULT_ERROR;
		} else {
			if (!rtf_attrstack_push_express(preader, ATTR_EXPAND, num / 4))
				return CMD_RESULT_ERROR;
		}
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_emboss(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!rtf_attrstack_find_pop_express(preader, ATTR_EMBOSS))
			return CMD_RESULT_ERROR;
	} else {
		if (!rtf_attrstack_push_express(preader, ATTR_EMBOSS, num))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_engrave(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!rtf_attrstack_pop_express(preader, ATTR_ENGRAVE))
			return CMD_RESULT_ERROR;
	} else {
		if (!rtf_attrstack_push_express(preader, ATTR_ENGRAVE, num))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_caps(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!rtf_attrstack_pop_express(preader, ATTR_CAPS))
			return CMD_RESULT_ERROR;
	} else { 
		if (!rtf_attrstack_push_express(preader, ATTR_CAPS, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_scaps(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!rtf_attrstack_pop_express(preader, ATTR_SMALLCAPS))
			return CMD_RESULT_ERROR;
	} else { 
		if (!rtf_attrstack_push_express(preader, ATTR_SMALLCAPS, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_bullet(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (preader->ext_push.p_bytes(TAG_CHARS_BULLET,
	    sizeof(TAG_CHARS_BULLET) - 1) != EXT_ERR_SUCCESS)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_ldblquote(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (preader->ext_push.p_bytes(TAG_CHARS_LEFT_DBL_QUOTE,
	    sizeof(TAG_CHARS_LEFT_DBL_QUOTE) - 1) != EXT_ERR_SUCCESS)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_rdblquote(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (preader->ext_push.p_bytes(TAG_CHARS_RIGHT_DBL_QUOTE,
	    sizeof(TAG_CHARS_RIGHT_DBL_QUOTE) - 1) != EXT_ERR_SUCCESS)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_lquote(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (preader->ext_push.p_bytes(TAG_CHARS_LEFT_QUOTE,
	    sizeof(TAG_CHARS_LEFT_QUOTE) - 1) != EXT_ERR_SUCCESS)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_nonbreaking_space(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (preader->ext_push.p_bytes(TAG_CHARS_NONBREAKING_SPACE,
	    sizeof(TAG_CHARS_NONBREAKING_SPACE) - 1) != EXT_ERR_SUCCESS)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_soft_hyphen(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (preader->ext_push.p_bytes(TAG_CHARS_SOFT_HYPHEN,
	    sizeof(TAG_CHARS_NONBREAKING_SPACE) - 1) != EXT_ERR_SUCCESS)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_optional_hyphen(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_emdash(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (preader->ext_push.p_bytes(TAG_CHARS_EMDASH,
	    sizeof(TAG_CHARS_EMDASH) - 1) != EXT_ERR_SUCCESS)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_endash(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (preader->ext_push.p_bytes(TAG_CHARS_ENDASH,
	    sizeof(TAG_CHARS_ENDASH) - 1) != EXT_ERR_SUCCESS)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_rquote(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (preader->ext_push.p_bytes(TAG_CHARS_RIGHT_QUOTE,
	    sizeof(TAG_CHARS_RIGHT_QUOTE) - 1) != EXT_ERR_SUCCESS)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_par(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (preader->have_fromhtml) {
		if (preader->ext_push.p_bytes("\r\n", 2) != EXT_ERR_SUCCESS)
			return CMD_RESULT_ERROR;
		return CMD_RESULT_CONTINUE;
	}
	if (preader->ext_push.p_bytes(TAG_LINE_BREAK,
	    sizeof(TAG_LINE_BREAK) - 1) != EXT_ERR_SUCCESS)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_line(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (preader->ext_push.p_bytes(TAG_LINE_BREAK,
	    sizeof(TAG_LINE_BREAK) - 1) != EXT_ERR_SUCCESS)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_page(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (preader->ext_push.p_bytes(TAG_PAGE_BREAK,
	    sizeof(TAG_PAGE_BREAK) - 1) != EXT_ERR_SUCCESS)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_intbl(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	preader->coming_pars_tabular ++;
	if (!rtf_check_for_table(preader))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_ulnone(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	int attr;
	
	while (true) {
		attr = rtf_attrstack_peek(preader);
		if (ATTR_UNDERLINE == attr || ATTR_DOT_UL == attr ||
			ATTR_DASH_UL == attr || ATTR_DOT_DASH_UL == attr||
		    ATTR_2DOT_DASH_UL == attr || ATTR_WORD_UL == attr ||
			ATTR_WAVE_UL == attr || ATTR_THICK_UL == attr ||
		    ATTR_DOUBLE_UL == attr) {
			if (!rtf_attrstack_pop_express(preader, attr))
				break;
		} else {
			break;
		}
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_ul(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool b_param, int num)
{
	if (b_param && num == 0)
		return rtf_cmd_ulnone(preader,
			pword, align, b_param, num);
	if (!rtf_attrstack_push_express(preader, ATTR_UNDERLINE, 0))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_uld(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool b_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_DOUBLE_UL, 0))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_uldb(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_DOT_UL, 0))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_uldash(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_DASH_UL, 0))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_uldashd(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_DOT_DASH_UL, 0))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_uldashdd(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_2DOT_DASH_UL, 0))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_ulw(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_WORD_UL, 0))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_ulth(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_THICK_UL, 0))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_ulthd(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_THICK_UL, 0))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_ulthdash(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_THICK_UL, 0))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_ulwave(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_WAVE_UL, 0))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_strike(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!rtf_attrstack_pop_express(preader, ATTR_STRIKE))
			return CMD_RESULT_ERROR;
	} else {
		if (!rtf_attrstack_push_express(preader, ATTR_STRIKE, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_strikedl(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!rtf_attrstack_pop_express(preader, ATTR_DBL_STRIKE))
			return CMD_RESULT_ERROR;
	} else {
		if (!rtf_attrstack_push_express(preader, ATTR_DBL_STRIKE, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_striked(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!rtf_attrstack_pop_express(preader, ATTR_DBL_STRIKE))
			return CMD_RESULT_ERROR;
	} else {
		if (!rtf_attrstack_push_express(preader, ATTR_DBL_STRIKE, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_shppict(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_up(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (have_param || num == 0) { // XXX
		if (!rtf_attrstack_pop_express(preader, ATTR_SUPER))
			return CMD_RESULT_ERROR;
	} else {
		if (!rtf_attrstack_push_express(preader, ATTR_SUPER, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_u(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	char tmp_string[8];
	
	wchar_to_utf8(num, tmp_string);
	if (!rtf_escape_output(preader, tmp_string))
		return CMD_RESULT_ERROR;
	if (preader->b_ubytes_switch)
		preader->ubytes_left = preader->ubytes_num;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_uc(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_UBYTES, num))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_dn(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!rtf_attrstack_pop_express(preader, ATTR_SUB))
			return CMD_RESULT_ERROR;
	} else {
		if (!rtf_attrstack_push_express(preader, ATTR_SUB, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_nosupersub(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!rtf_attrstack_pop_express(preader, ATTR_SUPER) ||
	    !rtf_attrstack_pop_express(preader, ATTR_SUB))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_super(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!rtf_attrstack_pop_express(preader, ATTR_SUPER))
			return CMD_RESULT_ERROR;
	} else {
		if (!rtf_attrstack_push_express(preader, ATTR_SUPER, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_sub(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!rtf_attrstack_pop_express(preader, ATTR_SUB))
			return CMD_RESULT_ERROR;
	} else {
		if (!rtf_attrstack_push_express(preader, ATTR_SUB, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_shad(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!rtf_attrstack_pop_express(preader, ATTR_SHADOW))
			return CMD_RESULT_ERROR;
	} else {
		if (!rtf_attrstack_push_express(preader, ATTR_SHADOW, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_b(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!rtf_attrstack_find_pop_express(preader, ATTR_BOLD))
			return CMD_RESULT_ERROR;
	} else {
		if (!rtf_attrstack_push_express(preader, ATTR_BOLD, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_i(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!rtf_attrstack_find_pop_express(preader, ATTR_ITALIC))
			return CMD_RESULT_ERROR;
	} else {
		if (!rtf_attrstack_push_express(preader, ATTR_ITALIC, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_s(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_sect(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (preader->ext_push.p_bytes(TAG_PARAGRAPH_BEGIN,
	    sizeof(TAG_PARAGRAPH_BEGIN) - 1) != EXT_ERR_SUCCESS)
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_shp(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_outl(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!rtf_attrstack_pop_express(preader, ATTR_OUTLINE))
			return CMD_RESULT_ERROR;
	} else {
		if (!rtf_attrstack_push_express(preader, ATTR_OUTLINE, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_ansi(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
    strcpy(preader->default_encoding, "windows-1252");
    return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_ansicpg(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	gx_strlcpy(preader->default_encoding, rtf_cpid_to_encoding(num), GX_ARRAY_SIZE(preader->default_encoding));
	preader->have_ansicpg = true;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_pc(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	strcpy(preader->default_encoding, "CP437");
    return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_pca(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	strcpy(preader->default_encoding, "CP850");
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_mac(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	strcpy(preader->default_encoding, "MAC");
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_colortbl(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	pword = pword->get_sibling();
	if (NULL != pword) {
		rtf_process_color_table(preader, pword);
	}
	return CMD_RESULT_IGNORE_REST;
}

static int rtf_cmd_fonttbl(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	pword = pword->get_sibling();
	if (NULL != pword) {
		if (!rtf_build_font_table(preader, pword))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_IGNORE_REST;
}

static int rtf_cmd_ignore(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return CMD_RESULT_IGNORE_REST;
}

static int rtf_cmd_maybe_ignore(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool b_param, int num)
{
	int param;
	char name[MAX_CONTROL_LEN];
	
	pword = pword->get_sibling();
	if (NULL != pword && NULL != pword->pdata &&
		'\\' == ((char*)pword->pdata)[0]) {
		if (rtf_parse_control(static_cast<char *>(pword->pdata) + 1,
			name, MAX_CONTROL_LEN, &param) < 0) {
			return CMD_RESULT_ERROR;
		}
		if (NULL != rtf_find_cmd_function(name)) {
			return CMD_RESULT_CONTINUE;
		}
	}
	return CMD_RESULT_IGNORE_REST;
}

static int rtf_cmd_info(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto pword1 = pword->get_sibling();
	if (NULL != pword1) {
		rtf_process_info_group(preader, pword1);
	}
	return CMD_RESULT_IGNORE_REST;
}

static int rtf_cmd_pict(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!rtf_attrstack_push_express(preader, ATTR_PICT, 0))
		return CMD_RESULT_ERROR;
	preader->picture_width = 0;
	preader->picture_height = 0;
	preader->picture_type = PICT_WB;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_bin(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_macpict(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	preader->picture_type = PICT_MAC;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_jpegblip(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	preader->picture_type = PICT_JPEG;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_pngblip(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	preader->picture_type = PICT_PNG;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_emfblip(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	preader->picture_type = PICT_EMF;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_pmmetafile(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	preader->picture_type = PICT_PM;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_wmetafile(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	preader->picture_type = PICT_WM;
	if (preader->is_within_picture && have_param) {
		preader->picture_wmf_type = num;
		switch (num) {
		case 1:
			preader->picture_wmf_str = "MM_TEXT";
			break;
		case 2:
			preader->picture_wmf_str = "MM_LOMETRIC";
			break;
		case 3:
			preader->picture_wmf_str = "MM_HIMETRIC";
			break;
		case 4:
			preader->picture_wmf_str = "MM_LOENGLISH";
			break;
		case 5:
			preader->picture_wmf_str = "MM_HIENGLISH";
			break;
		case 6:
			preader->picture_wmf_str = "MM_TWIPS";
			break;
		case 7:
			preader->picture_wmf_str = "MM_ISOTROPIC";
			break;
		case 8:
			preader->picture_wmf_str = "MM_ANISOTROPIC";
			break;
		default:
			preader->picture_wmf_str = "default:MM_TEXT";
			break;
		}
	}
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_wbmbitspixel(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (preader->is_within_picture && have_param)
		preader->picture_bits_per_pixel = num;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_picw(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (preader->is_within_picture && have_param)
		preader->picture_width = num;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_pich(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (preader->is_within_picture && have_param)
		preader->picture_height = num;
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_xe(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_tc(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	return CMD_RESULT_CONTINUE;
}

static int rtf_cmd_tcn(RTF_READER *preader, SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	return CMD_RESULT_IGNORE_REST;
}

static int rtf_cmd_htmltag(RTF_READER *preader, SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!preader->have_fromhtml)
		return CMD_RESULT_IGNORE_REST;
	if (!preader->is_within_htmltag)
		if (!rtf_attrstack_push_express(preader, ATTR_HTMLTAG, 0))
			return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static void rtf_unescape_string(char *string)
{
	int i;
	int tmp_len;
	
	tmp_len = strlen(string);
	for (i=0; i<tmp_len; i++) {
		if ('\\' == string[i] && ('\\' == string[i + 1] ||
			'{' == string[i + 1] || '}' == string[i + 1])) {
			memmove(string + i, string + 1, tmp_len - i);
			tmp_len --;
		}
	}
}

static int rtf_convert_group_node(RTF_READER *preader, SIMPLE_TREE_NODE *pnode)
{
	int ch;
	int num;
	int ret_val;
	char *string;
	BINARY tmp_bin;
	char cid_name[64];
	uint32_t tmp_int32;
	CMD_PROC_FUNC func;
	int paragraph_align;
	char picture_name[64];
	EXT_PUSH picture_push;
	const char *img_ctype = nullptr, *pext = nullptr;
	bool b_paragraph_begun = false, b_hyperlinked = false;
	char name[MAX_CONTROL_LEN];
	ATTACHMENT_CONTENT *pattachment;
	bool have_param = false, is_cell_group = false, b_picture_push = false;
	
	paragraph_align = ALIGN_LEFT;
	if (pnode->get_depth() >= MAX_GROUP_DEPTH) {
		debug_info("[rtf]: max group depth reached");
		return -ELOOP;
	}
	if (!rtf_check_for_table(preader) || !rtf_stack_list_new_node(preader))
		return -EINVAL;
	while (NULL != pnode) {    
		if (NULL != pnode->pdata) {
			if (preader->have_fromhtml) {
				if (strcasecmp(static_cast<char *>(pnode->pdata), "\\htmlrtf") == 0 ||
				    strcasecmp(static_cast<char *>(pnode->pdata), "\\htmlrtf1") == 0) {
					preader->is_within_htmlrtf = true;
				} else if (strcasecmp(static_cast<char *>(pnode->pdata), "\\htmlrtf0") == 0) {
					preader->is_within_htmlrtf = false;
				}
				if (preader->is_within_htmlrtf) {
					pnode = pnode->get_sibling();
					continue;
				}
			}
			if (strncmp(static_cast<char *>(pnode->pdata), "\\'", 2) != 0) {
				if (!rtf_flush_iconv_cache(preader))
					return -EINVAL;
			}
			string = static_cast<char *>(pnode->pdata);
			if (*string == ' ' && preader->is_within_header) {
				/* do nothing  */
			} else if ('\\' != string[0]) {
				if (!rtf_starting_body(preader) ||
				    !rtf_starting_text(preader))
					return -EINVAL;
				if (!b_paragraph_begun) {
					if (!rtf_starting_paragraph_align(preader, paragraph_align))
						return -EINVAL;
					b_paragraph_begun = true;
				}
				if (preader->is_within_picture) {
					if (!rtf_starting_body(preader))
						return -EINVAL;
					if (!b_picture_push) {
						switch (preader->picture_type) {
							case PICT_WB:
								img_ctype = "image/bmp";
								pext = "bmp";
								break;
							case PICT_WM:
								img_ctype = "application/x-msmetafile";
								pext = "wmf";
								break;
							case PICT_MAC:
								img_ctype = "image/x-pict";
								pext = "pict";
								break;
							case PICT_JPEG:
								img_ctype = "image/jpeg";
								 pext = "jpg";
								break;
							case PICT_PNG:
								img_ctype = "image/png";
								pext = "png";
								break;
							case PICT_DI:
								img_ctype = "image/bmp";
								pext = "dib";
								break;
							case PICT_PM:
								img_ctype = "application/octet-stream";
								pext = "pmm";
								break;
							case PICT_EMF:
								img_ctype = "image/x-emf";
								pext = "emf";
								break;
						}
						sprintf(picture_name, "picture%04d.%s",
							preader->picture_file_number, pext);
						sprintf(cid_name, "\"cid:picture%04d@rtf\"", 
								preader->picture_file_number);
						preader->picture_file_number ++;
						if (!picture_push.init(nullptr, 0, 0))
							return -ENOMEM;
						b_picture_push = true;
					}
					if (' ' != string[0]) {
						if (0 != preader->picture_width &&
							0 != preader->picture_height &&
							0 != preader->picture_bits_per_pixel) {
							if (picture_push.p_bytes(string, strlen(string)) != EXT_ERR_SUCCESS)
								return -ENOBUFS;
						}
					}
				} else {
					rtf_unescape_string(string);
					preader->total_chars_in_line += strlen(string);
					if (!rtf_escape_output(preader, string))
						return -ENOMEM;
				}
			} else if (string[1] == '\\' || string[1] == '{' || string[1] == '}') {
				rtf_unescape_string(string);
				preader->total_chars_in_line += strlen(string);
				if (!rtf_escape_output(preader, string))
					return -EINVAL;
			} else {
				string ++;
				if (0 == strcmp("ql", string)) {
					paragraph_align = ALIGN_LEFT;
				} else if (0 == strcmp("qr", string)) {
					paragraph_align = ALIGN_RIGHT;
				} else if (0 == strcmp("qj", string)) {
					paragraph_align = ALIGN_JUSTIFY;
				} else if (0 == strcmp("qc", string)) {
					paragraph_align = ALIGN_CENTER;
				} else if (0 == strcmp("pard", string)) {
					/* clear out all font attributes */
					rtf_attrstack_pop_express_all(preader);
					if (0 != preader->coming_pars_tabular) {
						preader->coming_pars_tabular --;
					}
					/* clear out all paragraph attributes */
					if (!rtf_ending_paragraph_align(preader, paragraph_align))
						return -EINVAL;
					paragraph_align = ALIGN_LEFT;
					b_paragraph_begun = false;
				} else if (0 == strcmp(string, "cell")) {
					is_cell_group = true;
					if (!preader->b_printed_cell_begin) {
						if (preader->ext_push.p_bytes(TAG_TABLE_CELL_BEGIN, sizeof(TAG_TABLE_CELL_BEGIN) - 1) != EXT_ERR_SUCCESS)
							return -ENOBUFS;
						rtf_attrstack_express_all(preader);
					}
					rtf_attrstack_pop_express_all(preader);
					if (preader->ext_push.p_bytes(TAG_TABLE_CELL_END, sizeof(TAG_TABLE_CELL_END) - 1) != EXT_ERR_SUCCESS)
						return -ENOBUFS;
					preader->b_printed_cell_begin = false;
					preader->b_printed_cell_end = true;
				} else if (0 == strcmp(string, "row")) {
					if (preader->is_within_table) {
						if (preader->ext_push.p_bytes(TAG_TABLE_ROW_END, sizeof(TAG_TABLE_ROW_END) - 1) != EXT_ERR_SUCCESS)
							return -ENOBUFS;
						preader->b_printed_row_begin = false;
						preader->b_printed_row_end = true;
					}
				} else if (string[0] == '\'' && string[1] != '\0' && string[2] != '\0') {
					ch = rtf_decode_hex_char(string + 1);
					if (!rtf_put_iconv_cache(preader, ch))
						return -EINVAL;
				} else {
					ret_val = rtf_parse_control(string,
						name, MAX_CONTROL_LEN, &num);
					if (ret_val < 0) {
						return -EINVAL;
					} else if (ret_val > 0) {
						have_param = true;
					} else {
						have_param = false;
						/* \b is like \b1 */
						num = 1;
					}
					if (preader->have_fromhtml) {
						if (0 == strcmp("par", name) ||
							0 == strcmp("tab", name) ||
							0 == strcmp("lquote", name) ||
							0 == strcmp("rquote", name) ||
							0 == strcmp("ldblquote", name) ||
							0 == strcmp("rdblquote", name) ||
							0 == strcmp("bullet", name) ||
							0 == strcmp("endash", name) ||
							0 == strcmp("emdash", name) ||
							0 == strcmp("colortbl", name) ||
							0 == strcmp("fonttbl", name) ||
							0 == strcmp("htmltag", name) ||
							0 == strcmp("uc", name) ||
							0 == strcmp("u", name) ||
							0 == strcmp("f", name) ||
							0 == strcmp("~", name) ||
							0 == strcmp("_", name)) {
							func = rtf_find_cmd_function(name);
						} else {
							func = NULL;
						}
					} else {
						func = rtf_find_cmd_function(name);
					}
					if (NULL != func) {
						switch (func(preader, pnode,
							paragraph_align, have_param, num)) {
						case CMD_RESULT_ERROR:
							return -EINVAL;
						case CMD_RESULT_CONTINUE:
							break;
						case CMD_RESULT_HYPERLINKED:
							b_hyperlinked = true;
							break;
						case CMD_RESULT_IGNORE_REST:
							while ((pnode = pnode->get_sibling()) != nullptr)
								/* nothing */;
							break;
						}
					}
				}
			}
		} else {
			auto pchild = pnode->get_child();
			if (!b_paragraph_begun) {
				if (!rtf_starting_paragraph_align(preader, paragraph_align))
					return -EINVAL;
				b_paragraph_begun = true;
			}
			if (NULL != pchild)  {
				auto ret = rtf_convert_group_node(preader, pchild);
				if (ret != 0)
					return -EINVAL;
			}
		}
		if (NULL != pnode) {
			pnode = pnode->get_sibling();
		}
	}
	if (preader->is_within_picture && b_picture_push) {
		if (picture_push.m_offset > 0) {
			tmp_bin.cb = picture_push.m_offset / 2;
			tmp_bin.pv = malloc(tmp_bin.cb);
			if (tmp_bin.pv == nullptr)
				return -EINVAL;
			if (picture_push.p_uint8(0) != EXT_ERR_SUCCESS) {
				free(tmp_bin.pv);
				return -EINVAL;
			}
			if (!decode_hex_binary(picture_push.m_cdata, tmp_bin.pv, tmp_bin.cb)) {
				free(tmp_bin.pv);
				return -EINVAL;
			}
			pattachment = attachment_content_init();
			if (NULL == pattachment) {
				free(tmp_bin.pv);
				return -EINVAL;
			}
			if (!attachment_list_append_internal(preader->pattachments, pattachment)) {
				free(tmp_bin.pv);
				return -EINVAL;
			}
			int ret;
			tmp_int32 = ATT_MHTML_REF;
			if ((ret = pattachment->proplist.set(PR_ATTACH_MIME_TAG, img_ctype)) != 0 ||
			    (ret = pattachment->proplist.set(PR_ATTACH_CONTENT_ID, cid_name)) != 0 ||
			    (ret = pattachment->proplist.set(PR_ATTACH_EXTENSION, pext)) != 0 ||
			    (ret = pattachment->proplist.set(PR_ATTACH_LONG_FILENAME, picture_name)) != 0 ||
			    (ret = pattachment->proplist.set(PR_ATTACH_FLAGS, &tmp_int32)) != 0 ||
			    (ret = pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin)) != 0) {
				free(tmp_bin.pv);
				return ret;
			}
			free(tmp_bin.pv);
			if (preader->ext_push.p_bytes(TAG_IMAGELINK_BEGIN, sizeof(TAG_IMAGELINK_BEGIN) - 1) != EXT_ERR_SUCCESS ||
			    preader->ext_push.p_bytes(cid_name, strlen(cid_name)) != EXT_ERR_SUCCESS ||
			    preader->ext_push.p_bytes(TAG_IMAGELINK_END, sizeof(TAG_IMAGELINK_END) - 1) != EXT_ERR_SUCCESS)
				return -EINVAL;
		}
		preader->is_within_picture = false;
	}
	if (!rtf_flush_iconv_cache(preader))
		return -EINVAL;
	if (b_hyperlinked) {
		if (preader->ext_push.p_bytes(TAG_HYPERLINK_END,
		    sizeof(TAG_HYPERLINK_END) - 1) != EXT_ERR_SUCCESS)
			return -EINVAL;
	}
	if (!is_cell_group)
		if (!rtf_attrstack_pop_express_all(preader))
			return -EINVAL;
	if (b_paragraph_begun) {
		if (!rtf_ending_paragraph_align(preader, paragraph_align))
			return -EINVAL;
	}
	rtf_stack_list_free_node(preader);
	return 0;
}

bool rtf_to_html(const char *pbuff_in, size_t length, const char *charset,
    char **pbuff_out, size_t *plength, ATTACHMENT_LIST *pattachments)
{
	int i;
	int tmp_len;
	iconv_t conv_id;
	char *pout;
	RTF_READER reader;
	char tmp_buff[128];
	SIMPLE_TREE_NODE *pnode;
	
	*pbuff_out = nullptr;
	if (!rtf_init_reader(&reader, pbuff_in, length, pattachments))
		return false;
	if (!rtf_load_element_tree(&reader)) {
		return false;
	}
	auto proot = reader.element_tree.get_root();
	if (NULL == proot) {
		return false;
	}
	for (pnode = proot->get_child(), i = 1; i <= 10 && pnode != nullptr; ++i) {
		if (NULL == pnode->pdata) {
			break;
		}
		if (strcmp(static_cast<char *>(pnode->pdata), "\\fromhtml1") == 0)
			reader.have_fromhtml = true;
		pnode = pnode->get_sibling();
	}
	if (!reader.have_fromhtml) {
		QRF(reader.ext_push.p_bytes(TAG_DOCUMENT_BEGIN, sizeof(TAG_DOCUMENT_BEGIN) - 1));
		QRF(reader.ext_push.p_bytes(TAG_HEADER_BEGIN, sizeof(TAG_HEADER_BEGIN) - 1));
		tmp_len = snprintf(tmp_buff, arsizeof(tmp_buff), TAG_HTML_CHARSET, charset);
		QRF(reader.ext_push.p_bytes(tmp_buff, tmp_len));
	}
	auto ret = rtf_convert_group_node(&reader, proot);
	if (ret != 0)
		return false;
	if (!rtf_end_table(&reader)) {
		return false;
	}
	if (!reader.have_fromhtml) {
		QRF(reader.ext_push.p_bytes(TAG_BODY_END, sizeof(TAG_BODY_END) - 1));
		QRF(reader.ext_push.p_bytes(TAG_DOCUMENT_END, sizeof(TAG_DOCUMENT_END) - 1));
	}
	if (0 == strcasecmp(charset, "UTF-8") ||
		0 == strcasecmp(charset, "ASCII") ||
		0 == strcasecmp(charset, "US-ASCII")) {
		*pbuff_out = me_alloc<char>(reader.ext_push.m_offset);
		if (*pbuff_out == nullptr) {
			return false;
		}
		memcpy(*pbuff_out, reader.ext_push.m_udata, reader.ext_push.m_offset);
		*plength = reader.ext_push.m_offset;
		return true;
	}
	snprintf(tmp_buff, 128, "%s//TRANSLIT",
		replace_iconv_charset(charset));
	conv_id = iconv_open(tmp_buff, "UTF-8");
	if ((iconv_t)-1 == conv_id) {
		return false;
	}
	auto pin = reader.ext_push.m_cdata;
	/* Assumption for 3x is that no codepage maps to points beyond BMP */
	*plength = 3 * reader.ext_push.m_offset;
	size_t out_len = *plength;
	*pbuff_out = me_alloc<char>(out_len + 1);
	if (*pbuff_out == nullptr) {
		iconv_close(conv_id);
		return false;
	}
	pout = *pbuff_out;
	size_t in_len = reader.ext_push.m_offset;
	if (iconv(conv_id, &pin, &in_len, &pout, &out_len) == static_cast<size_t>(-1)) {
		iconv_close(conv_id);
		return false;
	}
	iconv_close(conv_id);
	*plength -= out_len;
	return true;
}

bool rtf_init_library(CPID_TO_CHARSET cpid_to_charset)
{
	static constexpr std::pair<const char *, CMD_PROC_FUNC> cmd_map[] = {
		{"*",				rtf_cmd_maybe_ignore},
		{"-",				rtf_cmd_optional_hyphen},
		{"_",				rtf_cmd_soft_hyphen},
		{"~",				rtf_cmd_nonbreaking_space},
		{"ansi",			rtf_cmd_ansi},
		{"ansicpg",			rtf_cmd_ansicpg},
		{"b",				rtf_cmd_b},
		{"bullet",			rtf_cmd_bullet},
		{"bin",				rtf_cmd_bin},
		{"blipuid",			rtf_cmd_ignore},
		{"caps",			rtf_cmd_caps},
		{"cb",				rtf_cmd_cb},
		{"cf",				rtf_cmd_cf},
		{"colortbl",		rtf_cmd_colortbl},
		{"deff",			rtf_cmd_deff},
		{"dn",				rtf_cmd_dn},
		{"emdash",			rtf_cmd_emdash},
		{"endash",			rtf_cmd_endash},
		{"embo",			rtf_cmd_emboss},
		{"expand",			rtf_cmd_expand},
		{"expnd",			rtf_cmd_expand},
		{"emfblip",			rtf_cmd_emfblip},
		{"f",				rtf_cmd_f},
		{"fdecor",			rtf_cmd_fdecor}, 
		{"fmodern",			rtf_cmd_fmodern},
		{"fnil",			rtf_cmd_fnil},
		{"fonttbl",			rtf_cmd_fonttbl},
		{"froman",			rtf_cmd_froman},
		{"fromhtml",		rtf_cmd_fromhtml},
		{"fs",				rtf_cmd_fs},
		{"fscript",			rtf_cmd_fscript},
		{"fswiss",			rtf_cmd_fswiss},
		{"ftech",			rtf_cmd_ftech},
		{"field",			rtf_cmd_field},
		{"footer",			rtf_cmd_ignore},
		{"footerf",			rtf_cmd_ignore},
		{"footerl",			rtf_cmd_ignore},
		{"footerr",			rtf_cmd_ignore},
		{"highlight",		rtf_cmd_highlight},
		{"header",			rtf_cmd_ignore},
		{"headerf",			rtf_cmd_ignore},
		{"headerl",			rtf_cmd_ignore},
		{"headerr",			rtf_cmd_ignore},
		{"hl",				rtf_cmd_ignore},
		{"htmltag",			rtf_cmd_htmltag},
		{"i",				rtf_cmd_i},
		{"info",			rtf_cmd_info},
		{"intbl",			rtf_cmd_intbl},
		{"impr",			rtf_cmd_engrave},
		{"jpegblip",		rtf_cmd_jpegblip},
		{"ldblquote",		rtf_cmd_ldblquote},
		{"line",			rtf_cmd_line},
		{"lquote",			rtf_cmd_lquote},
		{"mac",				rtf_cmd_mac},
		{"macpict",			rtf_cmd_macpict},
		{"nosupersub",		rtf_cmd_nosupersub},
		{"nonshppict",		rtf_cmd_ignore},
		{"outl",			rtf_cmd_outl},
		{"page",			rtf_cmd_page},
		{"par",				rtf_cmd_par},
		{"pc",				rtf_cmd_pc},
		{"pca",				rtf_cmd_pca},
		{"pich",			rtf_cmd_pich},
		{"pict",			rtf_cmd_pict},
		{"picprop",			rtf_cmd_ignore},
		{"picw",			rtf_cmd_picw},
		{"plain",			rtf_cmd_plain},
		{"pngblip",			rtf_cmd_pngblip},
		{"pmmetafile",		rtf_cmd_pmmetafile},
		{"emfblip",			rtf_cmd_emfblip},
		{"rdblquote",		rtf_cmd_rdblquote},
		{"rquote",			rtf_cmd_rquote},
		{"rtf",				rtf_cmd_rtf},
		{"s",				rtf_cmd_s},
		{"sect",			rtf_cmd_sect},
		{"scaps",			rtf_cmd_scaps},
		{"super",			rtf_cmd_super},
		{"sub",				rtf_cmd_sub},
		{"shad",			rtf_cmd_shad},
		{"strike",			rtf_cmd_strike},
		{"striked",			rtf_cmd_striked},
		{"strikedl",		rtf_cmd_strikedl},
		{"stylesheet",		rtf_cmd_ignore},
		{"shp",				rtf_cmd_shp},
		{"shppict",			rtf_cmd_shppict},
		{"tab",				rtf_cmd_tab},
		{"tc",				rtf_cmd_tc},
		{"tcn",				rtf_cmd_tcn},
		{"u",				rtf_cmd_u},
		{"uc",				rtf_cmd_uc},
		{"ul",				rtf_cmd_ul},
		{"up",				rtf_cmd_up},
		{"uld",				rtf_cmd_uld},
		{"uldash",			rtf_cmd_uldash},
		{"uldashd",			rtf_cmd_uldashd},
		{"uldashdd",		rtf_cmd_uldashdd},
		{"uldb",			rtf_cmd_uldb},
		{"ulnone",			rtf_cmd_ulnone},
		{"ulth",			rtf_cmd_ulth},
		{"ulthd",			rtf_cmd_ulthd},
		{"ulthdash",		rtf_cmd_ulthdash},
		{"ulw",				rtf_cmd_ulw},
		{"ulwave",			rtf_cmd_ulwave},
		{"wbmbitspixel",	rtf_cmd_wbmbitspixel},
		{"wmetafile",		rtf_cmd_wmetafile},
		{"xe",				rtf_cmd_xe}};
	
	if (g_cmd_hash.size() > 0)
		return true;
	rtf_cpid_to_charset = cpid_to_charset;
	try {
		g_cmd_hash.insert(cbegin(cmd_map), cend(cmd_map));
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "E-1543: ENOMEM\n");
		return false;
	}
	return true;
}
