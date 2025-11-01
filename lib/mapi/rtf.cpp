// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2025 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iconv.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <libHX/ctype_helper.h>
#include <libHX/defs.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/simple_tree.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#define QRF(expr) do { if (pack_result{expr} != pack_result::ok) return false; } while (false)

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

struct attrstack_node {
	uint8_t attr_stack[MAX_ATTRS]{};
	int attr_params[MAX_ATTRS]{};
	int tos = -1;
};

struct FONTENTRY {
	char name[MAX_FINTNAME_LEN];
	char encoding[32];
};

struct rtf_reader;
using CMD_PROC_FN   = int(SIMPLE_TREE_NODE *, int, bool, int);
using CMD_PROC_FUNC = int (rtf_reader::*)(SIMPLE_TREE_NODE *, int, bool, int);

struct rtf_reader final {
	rtf_reader() = default;
	~rtf_reader();
	NOMOVE(rtf_reader);

	bool init_reader(const char *, uint32_t, ATTACHMENT_LIST *);
	bool riconv_open(const char *);
	bool riconv_flush();
	bool put_iconv_cache(int);
	pack_result getchar(int *);
	void ungetchar(int);
	char *read_element();
	bool load_element_tree();
	bool process_info_group(SIMPLE_TREE_NODE *);
	int convert_group_node(SIMPLE_TREE_NODE *);
	bool express_begin_fontsize(int);
	bool express_end_fontsize(int);
	bool express_attr_begin(int, int);
	bool express_attr_end(int, int);
	bool astk_express_all();
	bool astk_pushx(int, int);
	bool astk_popx(int);
	bool astk_popx_all();
	bool astk_find_popx(int);
	int astk_peek() const;
	const int *stack_list_find_attr(int) const;
	bool start_body();
	bool start_text();
	bool start_par(int);
	bool end_par(int);
	bool begin_table();
	bool end_table();
	bool check_for_table();
	const FONTENTRY *lookup_font(int) const;
	bool build_font_table(SIMPLE_TREE_NODE *);
	bool escape_output(char *);
	bool push_text_encoded(const char *, size_t);
	bool word_output_date(SIMPLE_TREE_NODE *);
	int push_da_pic(EXT_PUSH &, const char *, const char *, const char *, const char *);

	CMD_PROC_FN cmd_ansi, cmd_ansicpg, cmd_b, cmd_bullet, cmd_caps, cmd_cb,
	cmd_cf, cmd_colortbl, cmd_continue, cmd_deff, cmd_dn, cmd_emboss,
	cmd_emdash, cmd_emfblip, cmd_endash, cmd_engrave, cmd_expand, cmd_f,
	cmd_fdecor, cmd_field, cmd_fmodern, cmd_fnil, cmd_fonttbl, cmd_froman,
	cmd_fs, cmd_fscript, cmd_fswiss, cmd_ftech, cmd_highlight, cmd_htmltag,
	cmd_i, cmd_ignore, cmd_info, cmd_intbl, cmd_jpegblip, cmd_ldblquote,
	cmd_line, cmd_lquote, cmd_mac, cmd_macpict, cmd_maybe_ignore,
	cmd_nonbreaking_space, cmd_nosupersub, cmd_outl, cmd_page, cmd_par,
	cmd_pc, cmd_pca, cmd_pich, cmd_pict, cmd_picw, cmd_plain,
	cmd_pmmetafile, cmd_pngblip, cmd_rdblquote, cmd_rquote, cmd_scaps,
	cmd_sect, cmd_shad, cmd_soft_hyphen, cmd_strike, cmd_striked,
	cmd_strikedl, cmd_sub, cmd_super, cmd_tab, cmd_u, cmd_uc, cmd_ul,
	cmd_uld, cmd_uldash, cmd_uldashd, cmd_uldashdd, cmd_uldb, cmd_ulnone,
	cmd_ulth, cmd_ulthd, cmd_ulthdash, cmd_ulw, cmd_ulwave, cmd_up,
	cmd_wbmbitspixel, cmd_wmetafile;

	bool is_within_table = false, b_printed_row_begin = false;
	bool b_printed_cell_begin = false, b_printed_row_end = false;
	bool b_printed_cell_end = false, b_simulate_smallcaps = false;
	bool b_simulate_allcaps = false, b_ubytes_switch = true;
	bool is_within_picture = false, have_printed_body = false;
	bool is_within_header = true, have_ansicpg = false;
	bool have_fromhtml = false, is_within_htmltag = false;
	bool is_within_htmlrtf = false;
	int coming_pars_tabular = 0, ubytes_num = 1, ubytes_left = 0;
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
	std::unordered_map<int, FONTENTRY> pfont_hash;
	std::vector<attrstack_node> attr_stack_list;
	EXT_PULL ext_pull{};
	EXT_PUSH ext_push{};
	int ungot_chars[3] = {-1, -1, -1}, last_returned_ch = 0;
	iconv_t conv_id{iconv_t(-1)};
	EXT_PUSH iconv_push{};
	SIMPLE_TREE element_tree{};
	ATTACHMENT_LIST *pattachments = nullptr;
};
using RTF_READER = rtf_reader;

}

enum {
	CMD_RESULT_ERROR = -1,
	CMD_RESULT_CONTINUE,
	CMD_RESULT_IGNORE_REST,
	CMD_RESULT_HYPERLINKED
};

static CMD_PROC_FUNC rtf_find_cmd_function(const char *);

static constexpr cpid_t CP_UNSET = static_cast<cpid_t>(-1);

static int rtf_decode_hex_char(const char *in)
{
	int retval;
	
	if (strlen(in) < 2)
		return 0;
	if (in[0] >= '0' && in[0] <= '9')
		retval = in[0] - '0';
	else if ((in[0] >= 'a' && in[0] <= 'f'))
		retval = in[0] - 'a' + 10;
	else if (in[0] >= 'A' && in[0] <= 'F')
		retval = in[0] - 'A' + 10;
	else
		return 0;
	retval <<= 4;
	if (in[1] >= '0' && in[1] <= '9')
		retval += in[1] - '0';
	else if ((in[1] >= 'a' && in[1] <= 'f'))
		retval += in[1] - 'a' + 10;
	else if (in[1] >= 'A' && in[1] <= 'F')
		retval += in[1] - 'A' + 10;
	else
		return 0;
	return retval;
}

bool rtf_reader::riconv_open(const char *fromcode)
{
	auto preader = this;
	if (*fromcode == '\0' || strcasecmp(preader->current_encoding, fromcode) == 0)
		return true;
	if ((iconv_t)-1 != preader->conv_id) {
		iconv_close(preader->conv_id);
		preader->conv_id = (iconv_t)-1;
	}
	auto cs = replace_iconv_charset(fromcode);
	preader->conv_id = iconv_open("UTF-8//TRANSLIT", cs);
	if ((iconv_t)-1 == preader->conv_id) {
		mlog(LV_ERR, "E-2114: iconv_open %s: %s", cs, strerror(errno));
		return false;
	}
	gx_strlcpy(preader->current_encoding, fromcode, std::size(preader->current_encoding));
	return true;
}

bool rtf_reader::escape_output(char *string)
{
	auto preader = this;
	size_t tmp_len = strlen(string);
	if (ubytes_left > 0 && tmp_len > 0) {
		auto skip = std::min(static_cast<size_t>(ubytes_left), tmp_len);
		ubytes_left -= skip;
		if (skip >= tmp_len)
			return true;
		string += skip;
		tmp_len -= skip;
	}
	
	if (preader->is_within_htmltag) {
		QRF(preader->ext_push.p_bytes(string, tmp_len));
		return true;
	}
	if (preader->b_simulate_allcaps)
		HX_strupper(string);
	if (preader->b_simulate_smallcaps)
		HX_strlower(string);
	for (size_t i = 0; i < tmp_len; ++i) {
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

bool rtf_reader::push_text_encoded(const char *string, size_t len)
{
	if (b_ubytes_switch && ubytes_left > 0 && len > 0) {
		auto skip = std::min(static_cast<size_t>(ubytes_left), len);
		string += skip;
		len -= skip;
		ubytes_left -= skip;
		if (len == 0)
			return true;
	}
	if (len == 0)
		return true;
	if (iconv_push.p_bytes(string, len) != pack_result::ok)
		return false;
	return riconv_flush();
}

bool rtf_reader::riconv_flush()
{
	char *out_buff;
	size_t out_size;
	auto preader = this;
	
	if (preader->iconv_push.m_offset == 0)
		return true;
	if ((iconv_t)-1 == preader->conv_id) {
		if ('\0' == preader->default_encoding[0]) {
			if (!riconv_open("windows-1252"))
				return false;
		} else {
			if (!riconv_open(preader->default_encoding))
				return false;
		}
	}
	size_t tmp_len = 4 * preader->iconv_push.m_offset;
	auto ptmp_buff = me_alloc<char>(tmp_len);
	if (ptmp_buff == nullptr)
		return false;
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
	if (!escape_output(ptmp_buff)) {
		free(ptmp_buff);
		return false;
	}
	free(ptmp_buff);
	preader->iconv_push.m_offset = 0;
	return true;
}

static const char *rtf_cpid_to_encoding(cpid_t num)
{
	auto encoding = cpid_to_cset(num);
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
		*name++ = *string++;
        len ++;
    }
	if (len == maxlen)
		return -1;
	*name = '\0';
	if (*string == '\0')
		return 0;
	if (*string != '-' && !HX_isdigit(*string))
		return -1;
	*pnum = strtol(string, nullptr, 0);
	return 1;
}

static uint32_t rtf_fcharset_to_cpid(int num)
{
    switch (num) {
		case 0: return 1252;
		case 1: return CP_ACP;
		case 2: return CP_SYMBOL;
		case 77: return /*CP_MACCP*/ 10000;
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
		//case 255: return CP_OEMCP;
    }
	return 1252;
}

const FONTENTRY *rtf_reader::lookup_font(int num) const
{
	static constexpr FONTENTRY fake_entries[] =
		{{FONTNIL_STR, ""}, {FONTROMAN_STR, ""},
		{FONTSWISS_STR, ""}, {FONTMODERN_STR, ""},
		{FONTSCRIPT_STR, ""}, {FONTDECOR_STR, ""},
		{FONTTECH_STR, ""}};
	
	if (num < 0)
		return &fake_entries[-num-1];
	auto preader = this;
	auto i = preader->pfont_hash.find(num);
	return i != preader->pfont_hash.cend() ? &i->second : nullptr;
}

bool rtf_reader::init_reader(const char *prtf_buff, uint32_t rtf_length,
    ATTACHMENT_LIST *pattachments)
{
	auto preader = this;
	preader->attr_stack_list.clear();
	preader->ext_pull.init(prtf_buff, rtf_length, [](size_t) -> void * { return nullptr; }, 0);
	if (!preader->ext_push.init(nullptr, 0, 0) ||
	    !preader->iconv_push.init(nullptr, 0, 0))
		return false;
	b_ubytes_switch = true;
	ubytes_num = 1;
	ubytes_left = 0;
	preader->pattachments = pattachments;
	return true;
}

static void rtf_delete_tree_node(SIMPLE_TREE_NODE *pnode)
{
	if (pnode->pdata != nullptr)
		free(pnode->pdata);
	free(pnode);
}

rtf_reader::~rtf_reader()
{
	auto preader = this;
	auto proot = preader->element_tree.get_root();
	if (proot != nullptr)
		preader->element_tree.destroy_node(proot, rtf_delete_tree_node);
	preader->element_tree.clear();
	if (preader->conv_id != iconv_t(-1))
		iconv_close(preader->conv_id);
}

bool rtf_reader::express_begin_fontsize(int size)
{
	auto preader = this;
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
	tmp_len = snprintf(tmp_buff, std::size(tmp_buff), TAG_FONTSIZE_BEGIN, size);
	QRF(preader->ext_push.p_bytes(tmp_buff, tmp_len));
	return true;
}

bool rtf_reader::express_end_fontsize(int size)
{
	auto preader = this;
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

bool rtf_reader::express_attr_begin(int attr, int param)
{
	auto preader = this;
	int tmp_len;
	const char *encoding;
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
		return express_begin_fontsize(param);
	case ATTR_FONTFACE: {
		auto pentry = lookup_font(param);
		if (NULL == pentry) {
			encoding = preader->default_encoding;
			mlog(LV_DEBUG, "rtf: invalid font number %d", param);
			tmp_len = gx_snprintf(tmp_buff, std::size(tmp_buff),
				TAG_FONT_BEGIN, DEFAULT_FONT_STR);
		} else {
			encoding = pentry->encoding;
			tmp_len = gx_snprintf(tmp_buff, std::size(tmp_buff),
				TAG_FONT_BEGIN, pentry->name);
		}
		if (!preader->have_fromhtml)
			QRF(preader->ext_push.p_bytes(tmp_buff, tmp_len));
		if (!riconv_open(encoding))
			return false;
		return true;
	}
	case ATTR_FOREGROUND:
		tmp_len = gx_snprintf(tmp_buff, std::size(tmp_buff),
			TAG_FOREGROUND_BEGIN, param);
		QRF(preader->ext_push.p_bytes(tmp_buff, tmp_len));
		return true;
	case ATTR_BACKGROUND: 
		tmp_len = gx_snprintf(tmp_buff, std::size(tmp_buff),
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
		if (!riconv_open(preader->default_encoding))
			return false;
		break;
	}
	return true;
}

const int *rtf_reader::stack_list_find_attr(int attr) const
{
	auto preader = this;
	if (preader->attr_stack_list.empty())
		return nullptr;
	auto pattrstack = preader->attr_stack_list.crbegin();
	for (int i = pattrstack->tos - 1; i >= 0; --i)
		if (attr == pattrstack->attr_stack[i])
			return &pattrstack->attr_params[i];
	for (++pattrstack; pattrstack != preader->attr_stack_list.crend(); ++pattrstack)
		for (int i = pattrstack->tos; i >= 0; --i)
			if (attr == pattrstack->attr_stack[i])
				return &pattrstack->attr_params[i];
	return NULL;
}

bool rtf_reader::express_attr_end(int attr, int param)
{
	auto preader = this;
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
		return express_end_fontsize(param);
	case ATTR_FONTFACE: 
		if (!preader->have_fromhtml)
			QRF(preader->ext_push.p_bytes(TAG_FONT_END, sizeof(TAG_FONT_END) - 1));
		/* Caution: no BREAK here */
	case ATTR_HTMLTAG: {
		if (attr == ATTR_HTMLTAG)
			preader->is_within_htmltag = false;
		auto pparam = stack_list_find_attr(ATTR_FONTFACE);
		if (NULL == pparam) {
			encoding = preader->default_encoding;
		} else {
			auto pentry = lookup_font(*pparam);
			encoding = pentry != nullptr ? pentry->encoding : preader->default_encoding;
		}
		if (!riconv_open(encoding))
			return false;
		return true;
	}
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

bool rtf_reader::astk_express_all()
{
	auto preader = this;
	if (preader->attr_stack_list.empty()) {
		mlog(LV_DEBUG, "rtf: no stack to express all attribute from");
		return true;
	}
	auto pattrstack = &*preader->attr_stack_list.crbegin();
	for (int i = 0; i <= pattrstack->tos; ++i)
		if (!express_attr_begin(pattrstack->attr_stack[i],
		    pattrstack->attr_params[i]))
			return false;
	return true;
}

bool rtf_reader::astk_pushx(int attr, int param)
{
	auto preader = this;
	if (preader->attr_stack_list.empty()) {
		mlog(LV_DEBUG, "rtf: cannot find stack node for pushing attribute");
		return false;
	}
	auto pattrstack = &*preader->attr_stack_list.rbegin();
	if (pattrstack->tos >= MAX_ATTRS - 1) {
		mlog(LV_DEBUG, "rtf: too many attributes");
		return false;
	}
	if (!start_body() || !start_text())
		return false;
	pattrstack->tos ++;
	pattrstack->attr_stack[pattrstack->tos] = attr;
	pattrstack->attr_params[pattrstack->tos] = param;
	return express_attr_begin(attr, param);
}

bool rtf_reader::astk_popx(int attr)
{
	auto preader = this;
	if (preader->attr_stack_list.empty())
		return true;
	auto pattrstack = preader->attr_stack_list.rbegin();
	if (pattrstack->tos < 0 || pattrstack->attr_stack[pattrstack->tos] != attr)
		return true;
	if (!express_attr_end(attr, pattrstack->attr_params[pattrstack->tos]))
		return false;
	pattrstack->tos--;
	return true;
}

int rtf_reader::astk_peek() const
{
	auto preader = this;
	if (preader->attr_stack_list.empty()) {
		mlog(LV_DEBUG, "rtf: cannot find stack node for peeking attribute");
		return ATTR_NONE;
	}
	auto pattrstack = &*preader->attr_stack_list.rbegin();
	return pattrstack->tos >= 0 ? pattrstack->attr_stack[pattrstack->tos] : ATTR_NONE;
}

bool rtf_reader::astk_popx_all()
{
	auto preader = this;
	if (preader->attr_stack_list.empty())
		return true;
	auto pattrstack = &*preader->attr_stack_list.rbegin();
	for (; pattrstack->tos>=0; pattrstack->tos--)
		if (!express_attr_end(pattrstack->attr_stack[pattrstack->tos],
		    pattrstack->attr_params[pattrstack->tos]))
			return false;
	return true;
}

bool rtf_reader::astk_find_popx(int attr)
{
	auto preader = this;
	int i;
	
	if (preader->attr_stack_list.empty()) {
		mlog(LV_DEBUG, "rtf: cannot find stack node for finding attribute");
		return true;
	}
	auto pattrstack = &*preader->attr_stack_list.rbegin();
	bool b_found = false;
	for (i=0; i<=pattrstack->tos; i++) {
		if (pattrstack->attr_stack[i] == attr) {
			b_found = true;
			break;
		}
	}
	if (!b_found) {
		mlog(LV_DEBUG, "rtf: cannot find attribute in stack node");
		return true;
	}
	for (i=pattrstack->tos; i>=0; i--) {
		if (!express_attr_end(pattrstack->attr_stack[i],
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
	for (; i <= pattrstack->tos; ++i)
		if (!express_attr_begin(pattrstack->attr_stack[i],
		    pattrstack->attr_params[i]))
			return false;
	return true;
}

void rtf_reader::ungetchar(int ch)
{
	auto preader = this;
	if (preader->ungot_chars[0] >= 0 && preader->ungot_chars[1] >= 0 &&
	    preader->ungot_chars[2] >= 0)
		mlog(LV_DEBUG, "rtf: more than 3 ungot chars");
	preader->ungot_chars[2] = preader->ungot_chars[1];
	preader->ungot_chars[1] = preader->ungot_chars[0];
	preader->ungot_chars[0] = ch;
}

pack_result rtf_reader::getchar(int *pch)
{
	auto preader = this;
	int ch;
	int8_t tmp_char;

	if (preader->ungot_chars[0] >= 0) {
		ch = preader->ungot_chars[0]; 
		preader->ungot_chars[0] = preader->ungot_chars[1]; 
		preader->ungot_chars[1] = preader->ungot_chars[2];
		preader->ungot_chars[2] = -1;
		preader->last_returned_ch = ch;
		*pch = ch;
		return pack_result::ok;
	}
	do {
		auto status = preader->ext_pull.g_int8(&tmp_char);
		if (status != pack_result::success)
			return status;
		ch = tmp_char;
		if (ch != '\n')
			continue;
		/* Convert \(newline) into \par here */
		if ('\\' == preader->last_returned_ch) {
			ungetchar(' ');
			ungetchar('r');
			ungetchar('a');
			ch = 'p';
			break;
		}
	} while (ch == '\r');
	if (ch == '\t')
		ch = ' ';
	preader->last_returned_ch = ch;
	*pch = ch;
	return pack_result::ok;
}

char *rtf_reader::read_element()
{
	auto preader = this;
	int ch, ch2;
	unsigned int ix;
	bool need_unget = false, have_whitespace = false;
	bool is_control_word = false, b_numeric_param = false;
	unsigned int current_max_length;
	
	
	ix = 0;
	current_max_length = 10;
	auto input_str = static_cast<char *>(calloc(1, current_max_length));
	if (NULL == input_str) {
		mlog(LV_DEBUG, "rtf: cannot allocate word storage");
		return NULL;
	}
	
	do {
		if (getchar(&ch) != pack_result::ok) {
			free(input_str);
			mlog(LV_DEBUG, "rtf: failed to get char from reader");
			return NULL;
		}
	} while ('\n' == ch);
	
	if (' ' == ch) {
		/* trm multiple space chars into one */
		while (' ' == ch) {
			if (getchar(&ch) != pack_result::ok) {
				free(input_str);
				mlog(LV_DEBUG, "rtf: failed to get char from reader");
				return NULL;
			}
			have_whitespace = true;
		}
		if (have_whitespace) {
			ungetchar(ch);
			input_str[0] = ' '; 
			input_str[1] = 0;
			return input_str;
		}
	}

	switch (ch) {
	case '\\':
		if (getchar(&ch2) != pack_result::ok) {
			free(input_str);
			mlog(LV_DEBUG, "rtf: failed to get char from reader");
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
			if (getchar(&ch) != pack_result::ok) {
				free(input_str);
				mlog(LV_DEBUG, "rtf: failed to get char from reader");
				return nullptr;
			}
			input_str[2] = ch;
			if (getchar(&ch) != pack_result::ok) {
				free(input_str);
				mlog(LV_DEBUG, "rtf: failed to get char from reader");
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
			if (getchar(&ch) != pack_result::ok) {
				free(input_str);
				mlog(LV_DEBUG, "rtf: failed to get char from reader");
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
					if (ch != ' ')
						need_unget = true;
					break;
				}
			}
		}
		
		input_str[ix++] = ch;
		if (ix == current_max_length) {
			current_max_length *= 2;
			auto input_new = re_alloc<char>(input_str, current_max_length);
			if (NULL == input_new) {
				free(input_str);
				mlog(LV_DEBUG, "rtf: out of memory");
				return NULL;
			}
			input_str = input_new;
		}
		if (getchar(&ch) != pack_result::ok) {
			free(input_str);
			mlog(LV_DEBUG, "rtf: failed to get char from reader");
			return NULL;
		}
	}
	if (need_unget)
		ungetchar(ch);
	input_str[ix] = '\0';
	if (strncmp(input_str, "\\bin", 4) == 0 && HX_isdigit(input_str[4]))
		preader->ext_pull.advance(strtol(input_str + 4, nullptr, 0));
	return input_str;
}

bool rtf_reader::load_element_tree()
{
	auto preader = this;
	char *input_word;
	tree_node *plast_group = nullptr, *plast_node = nullptr;
	
	while ((input_word = read_element()) != nullptr) {
		if (input_word[0] == '{') {
			free(input_word);
			auto pgroup = me_alloc<tree_node>();
			if (NULL == pgroup) {
				mlog(LV_DEBUG, "rtf: out of memory");
				return false;
			}
			pgroup->pdata = nullptr;
			if (plast_group == nullptr)
				preader->element_tree.set_root(pgroup);
			else if (plast_node != nullptr)
				preader->element_tree.insert_sibling(
					plast_node, pgroup,
					SIMPLE_TREE_INSERT_AFTER);
			else
				preader->element_tree.add_child(plast_group,
					pgroup, SIMPLE_TREE_ADD_LAST);
			plast_group = pgroup;
			plast_node = NULL;
			continue;
		} else if (input_word[0] == '}') {
			free(input_word);
			if (NULL == plast_group) {
				mlog(LV_DEBUG, "rtf: rtf format error, missing first '{'");
				return false;
			}
			plast_node  = plast_group;
			plast_group = plast_group->get_parent();
			if (plast_group == nullptr)
				return true;
			continue;
		}

		if (NULL == plast_group) {
			free(input_word);
			mlog(LV_DEBUG, "rtf: rtf format error, missing first '{'");
			return false;
		}
		auto pword = me_alloc<tree_node>();
		if (NULL == pword) {
			free(input_word);
			mlog(LV_DEBUG, "rtf: out of memory");
			return false;
		}
		pword->pdata = input_word;
		if (plast_node == nullptr)
			preader->element_tree.add_child(plast_group, pword,
				SIMPLE_TREE_ADD_LAST);
		else
			preader->element_tree.insert_sibling(plast_node,
				pword, SIMPLE_TREE_INSERT_AFTER);
		plast_node = pword;
	}
	/* incomplete RTF... pretend it's ok */
	return true;
}

bool rtf_reader::start_body()
{
	auto preader = this;
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

bool rtf_reader::start_text()
{
	auto preader = this;
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
		if (!astk_express_all())
			return false;
		preader->b_printed_cell_begin = true;
		preader->b_printed_cell_end = false;
	}
	return true;
}

bool rtf_reader::start_par(int align)
{
	auto preader = this;
	if (preader->is_within_header && align != ALIGN_LEFT &&
	    !start_body())
		return false;
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

bool rtf_reader::end_par(int align)
{
	auto preader = this;
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

bool rtf_reader::begin_table() try
{
	auto preader = this;
	preader->is_within_table = true;
	preader->b_printed_row_begin = false;
	preader->b_printed_cell_begin = false;
	preader->b_printed_row_end = false;
	preader->b_printed_cell_end = false;
	preader->attr_stack_list.emplace_back();
	if (!start_body())
		return false;
	QRF(preader->ext_push.p_bytes(TAG_TABLE_BEGIN, sizeof(TAG_TABLE_BEGIN) - 1));
	return true;
} catch (const std::bad_alloc &) {
	return false;
}

bool rtf_reader::end_table()
{
	auto preader = this;
	if (!preader->is_within_table)
		return true;
	if (!preader->b_printed_cell_end) {
		if (!astk_popx_all())
			return false;
		QRF(preader->ext_push.p_bytes(TAG_TABLE_CELL_END, sizeof(TAG_TABLE_CELL_END) - 1));
	}
	if (!preader->b_printed_row_end)
		QRF(preader->ext_push.p_bytes(TAG_TABLE_ROW_END, sizeof(TAG_TABLE_ROW_END) - 1));
	QRF(preader->ext_push.p_bytes(TAG_TABLE_END, sizeof(TAG_TABLE_END) - 1));
	preader->is_within_table = false;
	preader->b_printed_row_begin = false;
	preader->b_printed_cell_begin = false;
	preader->b_printed_row_end = false;
	preader->b_printed_cell_end = false;
	return true;
}

bool rtf_reader::check_for_table()
{
	auto preader = this;
	if (preader->coming_pars_tabular == 0 && preader->is_within_table)
		return end_table();
	else if (preader->coming_pars_tabular != 0 && !preader->is_within_table)
		return begin_table();
	return true;
}

bool rtf_reader::put_iconv_cache(int ch)
{
	auto preader = this;
	if (preader->b_ubytes_switch && preader->ubytes_left > 0) {
		preader->ubytes_left --;
		return true;
	}
	QRF(preader->iconv_push.p_uint8(ch));
	return true;
}

bool rtf_reader::build_font_table(SIMPLE_TREE_NODE *pword)
{
	auto preader = this;
	int ret;
	int num;
	int param;
	char *ptoken;
	char name[1024];
	FONTENTRY tmp_entry;
	char tmp_buff[1024];
	char tmp_name[MAX_CONTROL_LEN];
	
	do {
		auto pword2 = pword->get_child();
		if (pword2 == nullptr || pword2->pdata == nullptr)
			return true;
		do {
			if (rtf_parse_control(&pword2->cdata[1],
			    tmp_name, MAX_CONTROL_LEN, &num) > 0 &&
			    strcmp(tmp_name, "f") == 0)
				break;
		} while ((pword2 = pword2->get_sibling()) != nullptr);
		if (pword2 == nullptr)
			continue;
		if (num < 0) {
			mlog(LV_DEBUG, "rtf: illegal font id in font table");
			return false;
		}
		tmp_buff[0] = '\0';
		cpid_t cpid = CP_UNSET, fcharsetcp = CP_UNSET;
		size_t tmp_offset = 0;
		while ((pword2 = pword2->get_sibling()) != nullptr) {
			if (pword2->pdata == nullptr)
				continue;
			auto string = pword2->cdata;
			if ('\\' != string[0]) {
				auto tmp_len = strlen(string);
				if (tmp_len + tmp_offset > sizeof(tmp_buff) - 1) {
					mlog(LV_DEBUG, "rtf: invalid font name");
					return false;
				}
				memcpy(tmp_buff + tmp_offset, string, tmp_len);
				tmp_offset += tmp_len;
				continue;
			} else if (string[1] == '\'' && string[2] != '\0' && string[3] != '\0') {
				if (tmp_offset + 1 > sizeof(tmp_buff) - 1) {
					mlog(LV_DEBUG, "rtf: invalid font name");
					return false;
				}
				tmp_buff[tmp_offset++] = rtf_decode_hex_char(string + 2);
				continue;
			}
			ret = rtf_parse_control(string + 1,
			      tmp_name, MAX_CONTROL_LEN, &param);
			if (ret < 0) {
				mlog(LV_DEBUG, "rtf: illegal control word in font table");
				continue;
			} else if (ret == 0) {
				continue;
			}
			/* ret > 0 */
			if (0 == strcmp(tmp_name, "u")) {
				wchar_to_utf8(param, tmp_name);
				cpid_t tmp_cpid = cpid != CP_UNSET ? cpid :
				                   fcharsetcp != CP_UNSET ? fcharsetcp :
				                   static_cast<cpid_t>(1252);
				if (!string_utf8_to_mb(rtf_cpid_to_encoding(tmp_cpid),
				    tmp_name, name, std::size(name))) {
					mlog(LV_DEBUG, "rtf: invalid font name");
					return false;
				}
				auto tmp_len = strlen(name);
				if (tmp_len + tmp_offset >
				    sizeof(tmp_buff) - 1) {
					mlog(LV_DEBUG, "rtf: invalid font name");
					return false;
				}
				memcpy(tmp_buff + tmp_offset, name, tmp_len);
				tmp_offset += tmp_len;
			} else if (0 == strcmp(tmp_name, "fcharset")) {
				fcharsetcp = static_cast<cpid_t>(rtf_fcharset_to_cpid(param));
			} else if (0 == strcmp(tmp_name, "cpg")) {
				cpid = static_cast<cpid_t>(param);
			}
		}
		if (0 == tmp_offset) {
			mlog(LV_DEBUG, "rtf: invalid font name");
			return false;
		}
		tmp_buff[tmp_offset] = '\0';
		if (cpid == CP_UNSET)
			cpid = fcharsetcp;
		if (cpid != CP_UNSET)
			strcpy(tmp_entry.encoding, rtf_cpid_to_encoding(cpid));
		else if (strcasestr(name, "symbol") != nullptr)
			tmp_entry.encoding[0] = '\0';
		else
			strcpy(tmp_entry.encoding, "windows-1252");
		if (cpid == CP_UNSET)
			cpid = static_cast<cpid_t>(1252);
		if (!string_mb_to_utf8(rtf_cpid_to_encoding(cpid), tmp_buff,
		    name, std::size(name))) {
			mlog(LV_DEBUG, "rtf: invalid font name");
			strcpy(name, DEFAULT_FONT_STR);
		}
		ptoken = strchr(name, ';');
		if (ptoken != nullptr)
			*ptoken = '\0';
		gx_strlcpy(tmp_entry.name, name, std::size(tmp_entry.name));
		try {
			if (preader->pfont_hash.size() < MAX_FONTS)
				preader->pfont_hash.emplace(num, std::move(tmp_entry));
		} catch (const std::bad_alloc &) {
			mlog(LV_ERR, "E-1986: ENOMEM");
		}
	} while ((pword = pword->get_sibling()) != nullptr);
	if (*preader->default_encoding == '\0')
		strcpy(preader->default_encoding, "windows-1252");
	if (!preader->have_ansicpg) {
		auto pentry = lookup_font(default_font_number);
		strcpy(preader->default_encoding, pentry != nullptr ? pentry->encoding : "windows-1252");
	}
	return true;
}

bool rtf_reader::word_output_date(SIMPLE_TREE_NODE *pword)
{
	auto preader = this;
	int day;
	int hour;
	int year;
	int month;
	int minute;
	int tmp_len;
	char tmp_buff[32];
	
	day = 0;
	hour = -1;
	year = 0;
	month = 0;
	minute = -1;
	do {
		if (pword->pdata == nullptr)
			return false;
		auto string = pword->cdata;
		if ('\\' == *string) {
			string ++;
			if (0 == strncmp(string, "yr", 2) && HX_isdigit(string[2]))
				year = strtol(string + 2, nullptr, 0);
			else if (strncmp(string, "mo", 2) == 0 && HX_isdigit(string[2]))
				month = strtol(string + 2, nullptr, 0);
			else if (strncmp(string, "dy", 2) == 0 && HX_isdigit(string[2]))
				day = strtol(string + 2, nullptr, 0);
			else if (strncmp(string, "min", 3) == 0 && HX_isdigit(string[3]))
				minute = strtol(string + 3, nullptr, 0);
			else if (strncmp(string, "hr", 2) == 0 && HX_isdigit(string[2]))
				hour = strtol(string + 2, nullptr, 0);
		}
	} while ((pword = pword->get_sibling()) != nullptr);
	year   = std::max(-1, std::min(9999, year));
	month  = std::max(-1, std::min(99, month)); /* fit within %02d */
	day    = std::max(-1, std::min(99, day));
	hour   = std::max(-1, std::min(99, hour));
	minute = std::max(-1, std::min(99, minute));
	tmp_len = gx_snprintf(tmp_buff, std::size(tmp_buff), "%04d-%02d-%02d ", year, month, day);
	if (hour >= 0 && minute >= 0)
		tmp_len += snprintf(&tmp_buff[tmp_len], std::size(tmp_buff)-tmp_len, "%02d:%02d ", hour, minute);
	QRF(preader->ext_push.p_bytes(tmp_buff, tmp_len));
	return true;
}

bool rtf_reader::process_info_group(SIMPLE_TREE_NODE *pword)
{
	auto preader = this;
	int ch;

	for (; pword != nullptr; pword = pword->get_sibling()) {
		auto pchild = pword->get_child();
		if (pchild == nullptr)
			continue;
		if (pchild->pdata == nullptr)
			return true;
		if (strcmp(pchild->cdata, "\\title") == 0) {
			QRF(preader->ext_push.p_bytes(TAG_DOCUMENT_TITLE_BEGIN, sizeof(TAG_DOCUMENT_TITLE_BEGIN) - 1));
			for (auto pword2 = pchild->get_sibling();
			     pword2 != nullptr; pword2 = pword2->get_sibling()) {
				if (pword2->pdata == nullptr)
					continue;
				if (pword2->cdata[0] != '\\') {
					if (!riconv_flush())
						return false;
					auto slen = strlen(pword2->cdata);
					if (!push_text_encoded(pword2->cdata, slen))
						return false;
				} else if (pword2->cdata[1] == '\'') {
					ch = rtf_decode_hex_char(&pword2->cdata[2]);
					if (!put_iconv_cache(ch))
						return false;
				}
			}
			if (!riconv_flush())
				return false;
			QRF(preader->ext_push.p_bytes(TAG_DOCUMENT_TITLE_END, sizeof(TAG_DOCUMENT_TITLE_END) - 1));
		} else if (strcmp(pchild->cdata, "\\author") == 0) {
			QRF(preader->ext_push.p_bytes(TAG_DOCUMENT_AUTHOR_BEGIN, sizeof(TAG_DOCUMENT_AUTHOR_BEGIN) - 1));
			for (auto pword2 = pchild->get_sibling();
			     pword2 != nullptr; pword2 = pword2->get_sibling()) {
				if (pword2->pdata == nullptr)
					continue;
				if (pword2->cdata[0] != '\\') {
					if (!riconv_flush())
						return false;
					auto slen = strlen(pword2->cdata);
					if (!push_text_encoded(pword2->cdata, slen))
						return false;
				} else if (pword2->cdata[1] == '\'') {
					ch = rtf_decode_hex_char(&pword2->cdata[2]);
					if (!put_iconv_cache(ch))
						return false;
				}
			}
			if (!riconv_flush())
				return false;
			QRF(preader->ext_push.p_bytes(TAG_DOCUMENT_AUTHOR_END, sizeof(TAG_DOCUMENT_AUTHOR_END) - 1));
		} else if (strcmp(pchild->cdata, "\\creatim") == 0) {
			QRF(preader->ext_push.p_bytes(TAG_COMMENT_BEGIN, sizeof(TAG_COMMENT_BEGIN) - 1));
			QRF(preader->ext_push.p_bytes("creation date: ", 15));
			if (pchild->get_sibling() != nullptr &&
			    !word_output_date(pchild->get_sibling()))
				return false;
			QRF(preader->ext_push.p_bytes(TAG_COMMENT_END, sizeof(TAG_COMMENT_END) - 1));
		} else if (strcmp(pchild->cdata, "\\printim") == 0) {
			QRF(preader->ext_push.p_bytes(TAG_COMMENT_BEGIN, sizeof(TAG_COMMENT_BEGIN) - 1));
			QRF(preader->ext_push.p_bytes("last print date: ", 17));
			if (pchild->get_sibling() != nullptr &&
			    !word_output_date(pchild->get_sibling()))
				return false;
			QRF(preader->ext_push.p_bytes(TAG_COMMENT_END, sizeof(TAG_COMMENT_END) - 1));
		} else if (strcmp(pchild->cdata, "\\buptim") == 0) {
			QRF(preader->ext_push.p_bytes(TAG_COMMENT_BEGIN, sizeof(TAG_COMMENT_BEGIN) - 1));
			QRF(preader->ext_push.p_bytes("last backup date: ", 18));
			if (pchild->get_sibling() != nullptr &&
			    !word_output_date(pchild->get_sibling()))
					return false;
			QRF(preader->ext_push.p_bytes(TAG_COMMENT_END, sizeof(TAG_COMMENT_END) - 1));
		} else if (strcmp(pchild->cdata, "\\revtim") == 0) {
			QRF(preader->ext_push.p_bytes(TAG_COMMENT_BEGIN, sizeof(TAG_COMMENT_BEGIN) - 1));
			QRF(preader->ext_push.p_bytes("modified date: ", 15));
			if (pchild->get_sibling() != nullptr &&
			    !word_output_date(pchild->get_sibling()))
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
		if (pword->pdata == nullptr || preader->total_colors >= MAX_COLORS)
			break;
		if (strncmp("\\red", pword->cdata, 4) == 0) {
			r = strtol(&pword->cdata[4], nullptr, 0);
			while (r > 255)
				r >>= 8;
		} else if (strncmp("\\green", pword->cdata, 6) == 0) {
			g = strtol(&pword->cdata[6], nullptr, 0);
			while (g > 255)
				g >>= 8;
		} else if (strncmp("\\blue", pword->cdata, 5) == 0) {
			b = strtol(&pword->cdata[5], nullptr, 0);
			while (b > 255)
				b >>= 8;
		} else if (strcmp(pword->cdata, ";") == 0) {
			preader->color_table[preader->total_colors++] =
				(r << 16) | (g << 8) | b;
			if (preader->total_colors >= MAX_COLORS)
				return;
			r = 0;
			g = 0;
			b = 0;
		}
	} while ((pword = pword->get_sibling()) != nullptr);
}

int rtf_reader::cmd_continue(SIMPLE_TREE_NODE *, int, bool, int)
{
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_cf(SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	auto preader = this;
	if (!have_param || num < 0 || num >= preader->total_colors)
		mlog(LV_DEBUG, "rtf: font color change to %xh is invalid", num);
	else if (!astk_pushx(ATTR_FOREGROUND, color_table[num]))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_cb(SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	auto preader = this;
	if (!have_param || num < 0 || num >= preader->total_colors)
		mlog(LV_DEBUG, "rtf: font color change attempted is invalid");
	else if (!astk_pushx(ATTR_BACKGROUND, color_table[num]))
			return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_fs(SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (!have_param)
		return CMD_RESULT_CONTINUE;
	num /= 2;
	return astk_pushx(ATTR_FONTSIZE, num) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_field(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	int tmp_len;
	char tmp_buff[1024];
	bool b_endnotecitations = false;
	auto preader = this;
	
	do {
		auto pchild = pword->get_child();
		if (pchild == nullptr || pchild->pdata == nullptr)
			return CMD_RESULT_IGNORE_REST;
		if (strcmp(pchild->cdata, "\\fldrslt") == 0)
			return CMD_RESULT_CONTINUE;
		if (strcmp(pchild->cdata, "\\*") != 0)
			continue;
		for (auto pword2 = pchild->get_sibling(); pword2 != nullptr;
		     pword2 = pword2->get_sibling()) {
			if (pword2->pdata == nullptr ||
			    strcmp(pword2->cdata, "\\fldinst") != 0)
				continue;
			auto pword3 = pword2->get_sibling();
			if (pword3 != nullptr && pword3->pdata != nullptr &&
			    strcmp(pword3->cdata, "SYMBOL") == 0) {
				auto pword4 = pword3->get_sibling();
				while (pword4 != nullptr && pword4->pdata != nullptr &&
				    strcmp(pword4->cdata, " ") == 0)
					pword4 = pword4->get_sibling();
				if (NULL != pword4 && NULL != pword4->pdata) {
					int ch = strtol(pword4->cdata, nullptr, 0);
					if (!astk_pushx(ATTR_FONTFACE, -7))
						return CMD_RESULT_ERROR;
					tmp_len = snprintf(tmp_buff, std::size(tmp_buff),
					          TAG_UNISYMBOL_PRINT, ch);
					if (preader->ext_push.p_bytes(tmp_buff, tmp_len) != pack_result::ok)
						return CMD_RESULT_ERROR;
				}
			}
			for (; pword3 != nullptr; pword3 = pword3->get_sibling())
				if (pword3->get_child() != nullptr)
					break;
			if (pword3 != nullptr)
				pword3 = pword3->get_child();
			for (; pword3 != nullptr; pword3 = pword3->get_sibling()) {
				if (pword3->pdata == nullptr)
					return CMD_RESULT_CONTINUE;
				if (strcmp(pword3->cdata, "EN.CITE") == 0) {
					b_endnotecitations = true;
					continue;
				} else if (strcmp(pword3->cdata, "HYPERLINK") != 0) {
					continue;
				}
				if (b_endnotecitations)
					continue;
				auto pword4 = pword3->get_sibling();
				while (pword4 != nullptr && pword4->pdata != nullptr &&
				    strcmp(pword4->cdata, " ") == 0)
					pword4 = pword4->get_sibling();
				if (NULL != pword4 && NULL != pword4->pdata) {
					tmp_len = gx_snprintf(tmp_buff, std::size(tmp_buff),
						  TAG_HYPERLINK_BEGIN, pword4->cdata);
					if (preader->ext_push.p_bytes(tmp_buff, tmp_len) != pack_result::ok)
						return CMD_RESULT_ERROR;
					return CMD_RESULT_HYPERLINKED;
				}
			}
		}
	} while ((pword = pword->get_sibling()) != nullptr);
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_f(SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (!have_param)
		return CMD_RESULT_CONTINUE;
	auto pentry = lookup_font(num);
	if (pentry == nullptr || strcasestr(pentry->name, "symbol") != nullptr)
		return CMD_RESULT_CONTINUE;
	return astk_pushx(ATTR_FONTFACE, num) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_deff(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (have_param)
		preader->default_font_number = num;
    return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_highlight(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (!have_param || num < 0 || num >= preader->total_colors)
		mlog(LV_DEBUG, "rtf: font background "
			"color change attempted is invalid");
	else if (!astk_pushx(ATTR_BACKGROUND, color_table[num]))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_tab(SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	auto preader = this;
	int need;
	
	if (preader->have_fromhtml) {
		if (preader->ext_push.p_uint8(0x09) != pack_result::ok)
			return CMD_RESULT_ERROR;
		++preader->total_chars_in_line;
		return CMD_RESULT_CONTINUE;
	}
	need = 8 - preader->total_chars_in_line % 8;
	preader->total_chars_in_line += need;
	while (need > 0) {
		if (preader->ext_push.p_bytes(TAG_FORCED_SPACE,
		    sizeof(TAG_FORCED_SPACE) - 1) != pack_result::ok)
			return CMD_RESULT_ERROR;
		need--;
	}
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_plain(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return astk_popx_all() ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_fnil(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return astk_pushx(ATTR_FONTFACE, -1) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_froman(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return astk_pushx(ATTR_FONTFACE, -2) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_fswiss(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return astk_pushx(ATTR_FONTFACE, -3) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_fmodern(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return astk_pushx(ATTR_FONTFACE, -4) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_fscript(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return astk_pushx(ATTR_FONTFACE, -5) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_fdecor(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return astk_pushx(ATTR_FONTFACE, -6) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_ftech(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return astk_pushx(ATTR_FONTFACE, -7) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_expand(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (!have_param)
		return CMD_RESULT_CONTINUE;
	if (0 == num) {
		if (!astk_popx(ATTR_EXPAND))
			return CMD_RESULT_ERROR;
	} else {
		if (!astk_pushx(ATTR_EXPAND, num / 4))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_emboss(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!astk_find_popx(ATTR_EMBOSS))
			return CMD_RESULT_ERROR;
	} else {
		if (!astk_pushx(ATTR_EMBOSS, num))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_engrave(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!astk_popx(ATTR_ENGRAVE))
			return CMD_RESULT_ERROR;
	} else {
		if (!astk_pushx(ATTR_ENGRAVE, num))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_caps(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!astk_popx(ATTR_CAPS))
			return CMD_RESULT_ERROR;
	} else { 
		if (!astk_pushx(ATTR_CAPS, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_scaps(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!astk_popx(ATTR_SMALLCAPS))
			return CMD_RESULT_ERROR;
	} else { 
		if (!astk_pushx(ATTR_SMALLCAPS, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_bullet(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (preader->ext_push.p_bytes(TAG_CHARS_BULLET,
	    sizeof(TAG_CHARS_BULLET) - 1) != pack_result::ok)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_ldblquote(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (preader->ext_push.p_bytes(TAG_CHARS_LEFT_DBL_QUOTE,
	    sizeof(TAG_CHARS_LEFT_DBL_QUOTE) - 1) != pack_result::ok)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_rdblquote(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (preader->ext_push.p_bytes(TAG_CHARS_RIGHT_DBL_QUOTE,
	    sizeof(TAG_CHARS_RIGHT_DBL_QUOTE) - 1) != pack_result::ok)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_lquote(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (preader->ext_push.p_bytes(TAG_CHARS_LEFT_QUOTE,
	    sizeof(TAG_CHARS_LEFT_QUOTE) - 1) != pack_result::ok)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_nonbreaking_space(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (preader->ext_push.p_bytes(TAG_CHARS_NONBREAKING_SPACE,
	    sizeof(TAG_CHARS_NONBREAKING_SPACE) - 1) != pack_result::ok)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_soft_hyphen(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (preader->ext_push.p_bytes(TAG_CHARS_SOFT_HYPHEN,
	    sizeof(TAG_CHARS_NONBREAKING_SPACE) - 1) != pack_result::ok)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_emdash(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (preader->ext_push.p_bytes(TAG_CHARS_EMDASH,
	    sizeof(TAG_CHARS_EMDASH) - 1) != pack_result::ok)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_endash(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (preader->ext_push.p_bytes(TAG_CHARS_ENDASH,
	    sizeof(TAG_CHARS_ENDASH) - 1) != pack_result::ok)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_rquote(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (preader->ext_push.p_bytes(TAG_CHARS_RIGHT_QUOTE,
	    sizeof(TAG_CHARS_RIGHT_QUOTE) - 1) != pack_result::ok)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_par(SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	auto preader = this;
	if (preader->have_fromhtml) {
		return preader->ext_push.p_bytes("\r\n", 2) == pack_result::ok ?
		       CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
	}
	if (preader->ext_push.p_bytes(TAG_LINE_BREAK,
	    sizeof(TAG_LINE_BREAK) - 1) != pack_result::ok)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_line(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (preader->ext_push.p_bytes(TAG_LINE_BREAK,
	    sizeof(TAG_LINE_BREAK) - 1) != pack_result::ok)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_page(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (preader->ext_push.p_bytes(TAG_PAGE_BREAK,
	    sizeof(TAG_PAGE_BREAK) - 1) != pack_result::ok)
		return CMD_RESULT_ERROR;
	preader->total_chars_in_line ++;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_intbl(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	preader->coming_pars_tabular ++;
	return check_for_table() ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_ulnone(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	while (true) {
		auto attr = astk_peek();
		if (ATTR_UNDERLINE == attr || ATTR_DOT_UL == attr ||
			ATTR_DASH_UL == attr || ATTR_DOT_DASH_UL == attr||
		    ATTR_2DOT_DASH_UL == attr || ATTR_WORD_UL == attr ||
			ATTR_WAVE_UL == attr || ATTR_THICK_UL == attr ||
		    ATTR_DOUBLE_UL == attr) {
			if (!astk_popx(attr))
				break;
		} else {
			break;
		}
	}
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_ul(SIMPLE_TREE_NODE *pword, int align,
    bool b_param, int num)
{
	if (b_param && num == 0)
		return cmd_ulnone(pword, align, b_param, num);
	return astk_pushx(ATTR_UNDERLINE, 0) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_uld(SIMPLE_TREE_NODE *pword, int align,
    bool b_param, int num)
{
	return astk_pushx(ATTR_DOUBLE_UL, 0) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_uldb(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return astk_pushx(ATTR_DOT_UL, 0) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_uldash(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return astk_pushx(ATTR_DASH_UL, 0) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_uldashd(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return astk_pushx(ATTR_DOT_DASH_UL, 0) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_uldashdd(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return astk_pushx(ATTR_2DOT_DASH_UL, 0) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_ulw(SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	return astk_pushx(ATTR_WORD_UL, 0) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_ulth(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return astk_pushx(ATTR_THICK_UL, 0) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_ulthd(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return astk_pushx(ATTR_THICK_UL, 0) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_ulthdash(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return astk_pushx(ATTR_THICK_UL, 0) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_ulwave(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return astk_pushx(ATTR_WAVE_UL, 0) ? CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_strike(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!astk_popx(ATTR_STRIKE))
			return CMD_RESULT_ERROR;
	} else {
		if (!astk_pushx(ATTR_STRIKE, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_strikedl(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!astk_popx(ATTR_DBL_STRIKE))
			return CMD_RESULT_ERROR;
	} else {
		if (!astk_pushx(ATTR_DBL_STRIKE, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_striked(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!astk_popx(ATTR_DBL_STRIKE))
			return CMD_RESULT_ERROR;
	} else {
		if (!astk_pushx(ATTR_DBL_STRIKE, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_up(SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (have_param || num == 0) { // XXX
		if (!astk_popx(ATTR_SUPER))
			return CMD_RESULT_ERROR;
	} else {
		if (!astk_pushx(ATTR_SUPER, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_u(SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	char tmp_string[8];
	
	wchar_to_utf8(num, tmp_string);
	if (!escape_output(tmp_string))
		return CMD_RESULT_ERROR;
	auto preader = this;
	if (preader->b_ubytes_switch)
		preader->ubytes_left = preader->ubytes_num;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_uc(SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (!have_param)
		num = ubytes_num != 0 ? ubytes_num : 1;
	if (num < 0)
		num = 0;
	b_ubytes_switch = true;
	ubytes_num = num;
	ubytes_left = 0;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_dn(SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!astk_popx(ATTR_SUB))
			return CMD_RESULT_ERROR;
	} else {
		if (!astk_pushx(ATTR_SUB, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_nosupersub(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return astk_popx(ATTR_SUPER) && astk_popx(ATTR_SUB) ?
	       CMD_RESULT_CONTINUE : CMD_RESULT_ERROR;
}

int rtf_reader::cmd_super(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!astk_popx(ATTR_SUPER))
			return CMD_RESULT_ERROR;
	} else {
		if (!astk_pushx(ATTR_SUPER, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_sub(SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!astk_popx(ATTR_SUB))
			return CMD_RESULT_ERROR;
	} else {
		if (!astk_pushx(ATTR_SUB, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_shad(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!astk_popx(ATTR_SHADOW))
			return CMD_RESULT_ERROR;
	} else {
		if (!astk_pushx(ATTR_SHADOW, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_b(SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!astk_find_popx(ATTR_BOLD))
			return CMD_RESULT_ERROR;
	} else {
		if (!astk_pushx(ATTR_BOLD, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_i(SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!astk_find_popx(ATTR_ITALIC))
			return CMD_RESULT_ERROR;
	} else {
		if (!astk_pushx(ATTR_ITALIC, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_sect(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (preader->ext_push.p_bytes(TAG_PARAGRAPH_BEGIN,
	    sizeof(TAG_PARAGRAPH_BEGIN) - 1) != pack_result::ok)
		return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_outl(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	if (have_param && num == 0) {
		if (!astk_popx(ATTR_OUTLINE))
			return CMD_RESULT_ERROR;
	} else {
		if (!astk_pushx(ATTR_OUTLINE, 0))
			return CMD_RESULT_ERROR;
	}
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_ansi(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
    strcpy(preader->default_encoding, "windows-1252");
    return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_ansicpg(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto enc = rtf_cpid_to_encoding(static_cast<cpid_t>(num));
	auto preader = this;
	gx_strlcpy(preader->default_encoding, enc, std::size(preader->default_encoding));
	preader->have_ansicpg = true;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_pc(SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	auto preader = this;
	strcpy(preader->default_encoding, "CP437");
    return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_pca(SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	auto preader = this;
	strcpy(preader->default_encoding, "CP850");
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_mac(SIMPLE_TREE_NODE *pword, int align,
    bool have_param, int num)
{
	auto preader = this;
	strcpy(preader->default_encoding, "MAC");
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_colortbl(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	pword = pword->get_sibling();
	if (pword != nullptr)
		rtf_process_color_table(preader, pword);
	return CMD_RESULT_IGNORE_REST;
}

int rtf_reader::cmd_fonttbl(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	pword = pword->get_sibling();
	if (pword != nullptr && !build_font_table(pword))
		return CMD_RESULT_ERROR;
	return CMD_RESULT_IGNORE_REST;
}

int rtf_reader::cmd_ignore(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	return CMD_RESULT_IGNORE_REST;
}

int rtf_reader::cmd_maybe_ignore(SIMPLE_TREE_NODE *pword,
    int align, bool b_param, int num)
{
	int param;
	char name[MAX_CONTROL_LEN];
	
	pword = pword->get_sibling();
	if (pword == nullptr || pword->pdata == nullptr ||
	    pword->cdata[0] == '\\')
		return CMD_RESULT_IGNORE_REST;
	if (rtf_parse_control(&pword->cdata[1],
	    name, MAX_CONTROL_LEN, &param) < 0)
		return CMD_RESULT_ERROR;
	if (rtf_find_cmd_function(name) != nullptr)
		return CMD_RESULT_CONTINUE;
	return CMD_RESULT_IGNORE_REST;
}

int rtf_reader::cmd_info(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto pword1 = pword->get_sibling();
	if (pword1 != nullptr)
		process_info_group(pword1);
	return CMD_RESULT_IGNORE_REST;
}

int rtf_reader::cmd_pict(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (!astk_pushx(ATTR_PICT, 0))
		return CMD_RESULT_ERROR;
	preader->picture_width = 0;
	preader->picture_height = 0;
	preader->picture_type = PICT_WB;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_macpict(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	preader->picture_type = PICT_MAC;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_jpegblip(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	preader->picture_type = PICT_JPEG;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_pngblip(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	preader->picture_type = PICT_PNG;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_emfblip(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	preader->picture_type = PICT_EMF;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_pmmetafile(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	preader->picture_type = PICT_PM;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_wmetafile(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	preader->picture_type = PICT_WM;
	if (!preader->is_within_picture || !have_param)
		return CMD_RESULT_CONTINUE;
	preader->picture_wmf_type = num;
	static const char *pws[] = {
		"default:MM_TEXT", "MM_TEXT", "MM_LOMETRIC", "MM_HIMETRIC",
		"MM_LOENGLISH", "MM_HIENGLISH", "MM_TWIPS", "MM_ISOTROPIC",
		"MM_ANISOTROPIC"
	};
	preader->picture_wmf_str = num >= 0 && static_cast<size_t>(num) < std::size(pws) ?
	                           pws[num] : pws[0];
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_wbmbitspixel(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (preader->is_within_picture && have_param)
		preader->picture_bits_per_pixel = num;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_picw(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (preader->is_within_picture && have_param)
		preader->picture_width = num;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_pich(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (preader->is_within_picture && have_param)
		preader->picture_height = num;
	return CMD_RESULT_CONTINUE;
}

int rtf_reader::cmd_htmltag(SIMPLE_TREE_NODE *pword,
    int align, bool have_param, int num)
{
	auto preader = this;
	if (!preader->have_fromhtml)
		return CMD_RESULT_IGNORE_REST;
	if (!preader->is_within_htmltag)
		if (!astk_pushx(ATTR_HTMLTAG, 0))
			return CMD_RESULT_ERROR;
	return CMD_RESULT_CONTINUE;
}

static void rtf_unescape_string(char *string)
{
	auto tmp_len = strlen(string);
	for (size_t i = 0; i < tmp_len; ++i)
		if ('\\' == string[i] && ('\\' == string[i + 1] ||
			'{' == string[i + 1] || '}' == string[i + 1])) {
			memmove(string + i, string + 1, tmp_len - i);
			tmp_len --;
		}
}

static void pictype_to(unsigned int t, const char *&m, const char *&x)
{
	switch (t) {
	case PICT_WB: m = "image/bmp"; x = "bmp"; break;
	case PICT_WM: m = "application/x-msmetafile"; x = "wmf"; break;
	case PICT_MAC: m = "image/x-pict"; x = "pict"; break;
	case PICT_JPEG: m = "image/jpeg"; x = "jpg"; break;
	case PICT_PNG: m = "image/png"; x = "png"; break;
	case PICT_DI: m = "image/bmp"; x = "dib"; break;
	case PICT_PM: m = "application/octet-stream"; x = "pmm"; break;
	case PICT_EMF: m = "image/x-emf"; x = "emf"; break;
	}
}

static CMD_PROC_FUNC rtf_find_fromhtml_func(const char *s)
{
	for (const auto x : {"par", "tab", "lquote", "rquote", "ldblquote",
	     "rdblquote", "bullet", "endash", "emdash", "colortbl", "fonttbl",
	     "htmltag", "uc", "u", "f", "~", "_"})
		if (strcmp(s, x) == 0)
			return rtf_find_cmd_function(s);
	return nullptr;
}

int rtf_reader::push_da_pic(EXT_PUSH &picture_push, const char *img_ctype,
    const char *pext, const char *cid_name, const char *picture_name)
{
	auto reader = this;
	BINARY bin;

	bin.cb = picture_push.m_offset / 2;
	bin.pv = malloc(bin.cb);
	if (bin.pv == nullptr ||
	    picture_push.p_uint8(0) != pack_result::ok ||
	    !decode_hex_binary(picture_push.m_cdata, bin.pv, bin.cb)) {
		free(bin.pv);
		return -EINVAL;
	}
	auto atx = attachment_content_init();
	if (atx == nullptr || !reader->pattachments->append_internal(atx)) {
		free(bin.pv);
		return -EINVAL;
	}
	ec_error_t ret;
	uint32_t flags = ATT_MHTML_REF;
	if ((ret = atx->proplist.set(PR_ATTACH_MIME_TAG, img_ctype)) != ecSuccess ||
	    (ret = atx->proplist.set(PR_ATTACH_CONTENT_ID, cid_name)) != ecSuccess ||
	    (ret = atx->proplist.set(PR_ATTACH_EXTENSION, pext)) != ecSuccess ||
	    (ret = atx->proplist.set(PR_ATTACH_LONG_FILENAME, picture_name)) != ecSuccess ||
	    (ret = atx->proplist.set(PR_ATTACH_FLAGS, &flags)) != ecSuccess ||
	    (ret = atx->proplist.set(PR_ATTACH_DATA_BIN, &bin)) != ecSuccess) {
		free(bin.pv);
		return ece2nerrno(ret);
	}
	free(bin.pv);
	if (reader->ext_push.p_bytes(TAG_IMAGELINK_BEGIN, sizeof(TAG_IMAGELINK_BEGIN) - 1) != pack_result::ok ||
	    reader->ext_push.p_bytes(cid_name, strlen(cid_name)) != pack_result::ok ||
	    reader->ext_push.p_bytes(TAG_IMAGELINK_END, sizeof(TAG_IMAGELINK_END) - 1) != pack_result::ok)
		return -EINVAL;
	return 0;
}

int rtf_reader::convert_group_node(SIMPLE_TREE_NODE *pnode)
{
	int ch;
	int num;
	int ret_val;
	char cid_name[64];
	CMD_PROC_FUNC func;
	int paragraph_align;
	char picture_name[64];
	EXT_PUSH picture_push;
	const char *img_ctype = nullptr, *pext = nullptr;
	bool b_paragraph_begun = false, b_hyperlinked = false;
	char name[MAX_CONTROL_LEN];
	bool have_param = false, is_cell_group = false, b_picture_push = false;
	
	paragraph_align = ALIGN_LEFT;
	if (pnode->get_depth() >= MAX_GROUP_DEPTH) {
		mlog(LV_DEBUG, "rtf: max group depth reached");
		return -ELOOP;
	}
	if (!check_for_table())
		return -EINVAL;
	auto preader = this;
	auto uc_prev_active = b_ubytes_switch;
	auto uc_prev_num = ubytes_num;
	auto uc_guard = HX::make_scope_exit([&,this]() {
		b_ubytes_switch = uc_prev_active;
		ubytes_num = uc_prev_num;
		ubytes_left = 0;
	});
	try {
		preader->attr_stack_list.emplace_back();
	} catch (const std::bad_alloc &) {
		return -ENOMEM;
	}
	while (NULL != pnode) {    
		if (NULL != pnode->pdata) {
			if (preader->have_fromhtml) {
				if (strcasecmp(pnode->cdata, "\\htmlrtf") == 0 ||
				    strcasecmp(pnode->cdata, "\\htmlrtf1") == 0) {
					preader->is_within_htmlrtf = true;
				} else if (strcasecmp(pnode->cdata, "\\htmlrtf0") == 0) {
					preader->is_within_htmlrtf = false;
				}
				if (preader->is_within_htmlrtf) {
					pnode = pnode->get_sibling();
					continue;
				}
			}
			if (strncmp(pnode->cdata, "\\'", 2) != 0 &&
			    !riconv_flush())
				return -EINVAL;
			auto string = pnode->cdata;
			if (*string == ' ' && preader->is_within_header) {
				/* do nothing  */
			} else if ('\\' != string[0]) {
				if (!start_body() || !start_text())
					return -EINVAL;
				if (!b_paragraph_begun) {
					if (!start_par(paragraph_align))
						return -EINVAL;
					b_paragraph_begun = true;
				}
				if (preader->is_within_picture) {
					if (!start_body())
						return -EINVAL;
					if (!b_picture_push) {
						pictype_to(preader->picture_type, img_ctype, pext);
						sprintf(picture_name, "picture%04d.%s",
							preader->picture_file_number, pext);
						sprintf(cid_name, "\"cid:picture%04d@rtf\"", 
							preader->picture_file_number++);
						if (!picture_push.init(nullptr, 0, 0))
							return -ENOMEM;
						b_picture_push = true;
					}
					if (string[0] != ' ' &&
					    preader->picture_width != 0 &&
					    preader->picture_height != 0 &&
					    preader->picture_bits_per_pixel != 0 &&
					    picture_push.p_bytes(string, strlen(string)) != pack_result::ok)
						return -ENOBUFS;
				} else {
					rtf_unescape_string(string);
					auto slen = strlen(string);
					total_chars_in_line += slen;
					if (!push_text_encoded(string, slen))
						return -ENOMEM;
				}
			} else if (string[1] == '\\' || string[1] == '{' || string[1] == '}') {
				rtf_unescape_string(string);
				auto slen = strlen(string);
				total_chars_in_line += slen;
				if (!push_text_encoded(string, slen))
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
					astk_popx_all();
					if (preader->coming_pars_tabular != 0)
						preader->coming_pars_tabular --;
					/* clear out all paragraph attributes */
					if (!end_par(paragraph_align))
						return -EINVAL;
					paragraph_align = ALIGN_LEFT;
					b_paragraph_begun = false;
				} else if (0 == strcmp(string, "cell")) {
					is_cell_group = true;
					if (!preader->b_printed_cell_begin) {
						if (preader->ext_push.p_bytes(TAG_TABLE_CELL_BEGIN, sizeof(TAG_TABLE_CELL_BEGIN) - 1) != pack_result::ok)
							return -ENOBUFS;
						astk_express_all();
					}
					astk_popx_all();
					if (preader->ext_push.p_bytes(TAG_TABLE_CELL_END, sizeof(TAG_TABLE_CELL_END) - 1) != pack_result::ok)
						return -ENOBUFS;
					preader->b_printed_cell_begin = false;
					preader->b_printed_cell_end = true;
				} else if (0 == strcmp(string, "row")) {
					if (preader->is_within_table) {
						if (preader->ext_push.p_bytes(TAG_TABLE_ROW_END, sizeof(TAG_TABLE_ROW_END) - 1) != pack_result::ok)
							return -ENOBUFS;
						preader->b_printed_row_begin = false;
						preader->b_printed_row_end = true;
					}
				} else if (string[0] == '\'' && string[1] != '\0' && string[2] != '\0') {
					ch = rtf_decode_hex_char(string + 1);
					if (!put_iconv_cache(ch))
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


					func = preader->have_fromhtml ? rtf_find_fromhtml_func(name) : rtf_find_cmd_function(name);
					if (NULL != func) {
						switch ((preader->*func)(pnode,
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
				if (!start_par(paragraph_align))
					return -EINVAL;
				b_paragraph_begun = true;
			}
			if (NULL != pchild)  {
				auto ret = convert_group_node(pchild);
				if (ret != 0)
					return -EINVAL;
			}
		}
		if (pnode != nullptr)
			pnode = pnode->get_sibling();
	}
	if (preader->is_within_picture && b_picture_push) {
		if (picture_push.m_offset > 0) {
			auto ret = push_da_pic(picture_push, img_ctype,
			           pext, cid_name, picture_name);
			if (ret != 0)
				return -ret;
		}
		preader->is_within_picture = false;
	}
	if (!riconv_flush())
		return -EINVAL;
	if (b_hyperlinked && preader->ext_push.p_bytes(TAG_HYPERLINK_END,
	    sizeof(TAG_HYPERLINK_END) - 1) != pack_result::ok)
		return -EINVAL;
	if (!is_cell_group && !astk_popx_all())
		return -EINVAL;
	if (b_paragraph_begun && !end_par(paragraph_align))
		return -EINVAL;
	if (preader->attr_stack_list.size() > 0)
		preader->attr_stack_list.pop_back();
	return 0;
}

bool rtf_to_html(const char *pbuff_in, size_t length, const char *charset,
    std::string &buf_out, ATTACHMENT_LIST *pattachments) try
{
	int i;
	int tmp_len;
	iconv_t conv_id;
	RTF_READER reader;
	char tmp_buff[128];
	SIMPLE_TREE_NODE *pnode;
	
	if (!reader.init_reader(pbuff_in, length, pattachments) ||
	    !reader.load_element_tree())
		return false;
	auto proot = reader.element_tree.get_root();
	if (proot == nullptr)
		return false;
	for (pnode = proot->get_child(), i = 1; i <= 10 && pnode != nullptr; ++i) {
		if (pnode->pdata == nullptr)
			break;
		if (strcmp(pnode->cdata, "\\fromhtml1") == 0)
			reader.have_fromhtml = true;
		pnode = pnode->get_sibling();
	}
	if (!reader.have_fromhtml) {
		QRF(reader.ext_push.p_bytes(TAG_DOCUMENT_BEGIN, sizeof(TAG_DOCUMENT_BEGIN) - 1));
		QRF(reader.ext_push.p_bytes(TAG_HEADER_BEGIN, sizeof(TAG_HEADER_BEGIN) - 1));
		tmp_len = snprintf(tmp_buff, std::size(tmp_buff),
		          TAG_HTML_CHARSET, charset);
		QRF(reader.ext_push.p_bytes(tmp_buff, tmp_len));
	}
	auto ret = reader.convert_group_node(proot);
	if (ret != 0 || !reader.end_table())
		return false;
	if (!reader.have_fromhtml) {
		QRF(reader.ext_push.p_bytes(TAG_BODY_END, sizeof(TAG_BODY_END) - 1));
		QRF(reader.ext_push.p_bytes(TAG_DOCUMENT_END, sizeof(TAG_DOCUMENT_END) - 1));
	}
	if (0 == strcasecmp(charset, "UTF-8") ||
		0 == strcasecmp(charset, "ASCII") ||
		0 == strcasecmp(charset, "US-ASCII")) {
		buf_out.resize(reader.ext_push.m_offset);
		memcpy(buf_out.data(), reader.ext_push.m_udata, reader.ext_push.m_offset);
		return true;
	}
	snprintf(tmp_buff, 128, "%s//TRANSLIT",
		replace_iconv_charset(charset));
	conv_id = iconv_open(tmp_buff, "UTF-8");
	if ((iconv_t)-1 == conv_id) {
		mlog(LV_ERR, "E-2115: iconv_open %s: %s",
		        tmp_buff, strerror(errno));
		return false;
	}
	auto cl_0 = HX::make_scope_exit([&]() { iconv_close(conv_id); });
	auto pin = reader.ext_push.m_cdata;
	/* Assumption for 3x is that no codepage maps to points beyond BMP */
	size_t out_len = 3 * reader.ext_push.m_offset;
	buf_out.resize(out_len);
	auto pout = buf_out.data();
	size_t in_len = reader.ext_push.m_offset;
	if (iconv(conv_id, &pin, &in_len, &pout, &out_len) == static_cast<size_t>(-1))
		return false;
	buf_out.resize(buf_out.size() - out_len);
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1205: ENOMEM");
	return false;
}

static constexpr std::pair<const char *, CMD_PROC_FUNC> g_cmd_map[] = {
	{"*", &rtf_reader::cmd_maybe_ignore},
	{"-", &rtf_reader::cmd_continue},
	{"_", &rtf_reader::cmd_soft_hyphen},
	{"ansi", &rtf_reader::cmd_ansi},
	{"ansicpg", &rtf_reader::cmd_ansicpg},
	{"b", &rtf_reader::cmd_b},
	{"bin", &rtf_reader::cmd_continue},
	{"blipuid", &rtf_reader::cmd_ignore},
	{"bullet", &rtf_reader::cmd_bullet},
	{"caps", &rtf_reader::cmd_caps},
	{"cb", &rtf_reader::cmd_cb},
	{"cf", &rtf_reader::cmd_cf},
	{"colortbl", &rtf_reader::cmd_colortbl},
	{"deff", &rtf_reader::cmd_deff},
	{"dn", &rtf_reader::cmd_dn},
	{"embo", &rtf_reader::cmd_emboss},
	{"emdash", &rtf_reader::cmd_emdash},
	{"emfblip", &rtf_reader::cmd_emfblip},
	{"endash", &rtf_reader::cmd_endash},
	{"expand", &rtf_reader::cmd_expand},
	{"expnd", &rtf_reader::cmd_expand},
	{"f", &rtf_reader::cmd_f},
	{"fdecor", &rtf_reader::cmd_fdecor},
	{"field", &rtf_reader::cmd_field},
	{"fmodern", &rtf_reader::cmd_fmodern},
	{"fnil", &rtf_reader::cmd_fnil},
	{"fonttbl", &rtf_reader::cmd_fonttbl},
	{"footer", &rtf_reader::cmd_ignore},
	{"footerf", &rtf_reader::cmd_ignore},
	{"footerl", &rtf_reader::cmd_ignore},
	{"footerr", &rtf_reader::cmd_ignore},
	{"froman", &rtf_reader::cmd_froman},
	{"fromhtml", &rtf_reader::cmd_continue},
	{"fs", &rtf_reader::cmd_fs},
	{"fscript", &rtf_reader::cmd_fscript},
	{"fswiss", &rtf_reader::cmd_fswiss},
	{"ftech", &rtf_reader::cmd_ftech},
	{"header", &rtf_reader::cmd_ignore},
	{"headerf", &rtf_reader::cmd_ignore},
	{"headerl", &rtf_reader::cmd_ignore},
	{"headerr", &rtf_reader::cmd_ignore},
	{"highlight", &rtf_reader::cmd_highlight},
	{"hl", &rtf_reader::cmd_ignore},
	{"htmltag", &rtf_reader::cmd_htmltag},
	{"i", &rtf_reader::cmd_i},
	{"impr", &rtf_reader::cmd_engrave},
	{"info", &rtf_reader::cmd_info},
	{"intbl", &rtf_reader::cmd_intbl},
	{"jpegblip", &rtf_reader::cmd_jpegblip},
	{"ldblquote", &rtf_reader::cmd_ldblquote},
	{"line", &rtf_reader::cmd_line},
	{"lquote", &rtf_reader::cmd_lquote},
	{"mac", &rtf_reader::cmd_mac},
	{"macpict", &rtf_reader::cmd_macpict},
	{"nonshppict", &rtf_reader::cmd_ignore},
	{"nosupersub", &rtf_reader::cmd_nosupersub},
	{"outl", &rtf_reader::cmd_outl},
	{"page", &rtf_reader::cmd_page},
	{"par", &rtf_reader::cmd_par},
	{"pc", &rtf_reader::cmd_pc},
	{"pca", &rtf_reader::cmd_pca},
	{"pich", &rtf_reader::cmd_pich},
	{"picprop", &rtf_reader::cmd_ignore},
	{"pict", &rtf_reader::cmd_pict},
	{"picw", &rtf_reader::cmd_picw},
	{"plain", &rtf_reader::cmd_plain},
	{"pmmetafile", &rtf_reader::cmd_pmmetafile},
	{"pngblip", &rtf_reader::cmd_pngblip},
	{"rdblquote", &rtf_reader::cmd_rdblquote},
	{"rquote", &rtf_reader::cmd_rquote},
	{"rtf", &rtf_reader::cmd_continue},
	{"s", &rtf_reader::cmd_continue},
	{"scaps", &rtf_reader::cmd_scaps},
	{"sect", &rtf_reader::cmd_sect},
	{"shad", &rtf_reader::cmd_shad},
	{"shp", &rtf_reader::cmd_continue},
	{"shppict", &rtf_reader::cmd_continue},
	{"strike", &rtf_reader::cmd_strike},
	{"striked", &rtf_reader::cmd_striked},
	{"strikedl", &rtf_reader::cmd_strikedl},
	{"stylesheet", &rtf_reader::cmd_ignore},
	{"sub", &rtf_reader::cmd_sub},
	{"super", &rtf_reader::cmd_super},
	{"tab", &rtf_reader::cmd_tab},
	{"tc", &rtf_reader::cmd_continue},
	{"tcn", &rtf_reader::cmd_ignore},
	{"u", &rtf_reader::cmd_u},
	{"uc", &rtf_reader::cmd_uc},
	{"ul", &rtf_reader::cmd_ul},
	{"uld", &rtf_reader::cmd_uld},
	{"uldash", &rtf_reader::cmd_uldash},
	{"uldashd", &rtf_reader::cmd_uldashd},
	{"uldashdd", &rtf_reader::cmd_uldashdd},
	{"uldb", &rtf_reader::cmd_uldb},
	{"ulnone", &rtf_reader::cmd_ulnone},
	{"ulth", &rtf_reader::cmd_ulth},
	{"ulthd", &rtf_reader::cmd_ulthd},
	{"ulthdash", &rtf_reader::cmd_ulthdash},
	{"ulw", &rtf_reader::cmd_ulw},
	{"ulwave", &rtf_reader::cmd_ulwave},
	{"up", &rtf_reader::cmd_up},
	{"wbmbitspixel", &rtf_reader::cmd_wbmbitspixel},
	{"wmetafile", &rtf_reader::cmd_wmetafile},
	{"xe", &rtf_reader::cmd_continue},
	{"~", &rtf_reader::cmd_nonbreaking_space},
};

static CMD_PROC_FUNC rtf_find_cmd_function(const char *cmd)
{
	auto i = std::lower_bound(std::cbegin(g_cmd_map), std::cend(g_cmd_map), cmd,
	         [&](const std::pair<const char *, CMD_PROC_FUNC> &p, const char *c) {
	         	return strcasecmp(p.first, c) < 0;
	         });
	return i != std::cend(g_cmd_map) && strcasecmp(i->first, cmd) == 0 ?
	       i->second : nullptr;
}

bool rtf_init_library()
{
	textmaps_init();
	return true;
}
