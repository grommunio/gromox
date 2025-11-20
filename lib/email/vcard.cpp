// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/util.hpp>
#include <gromox/vcard.hpp>
#define MAX_LINE							73

using namespace gromox;

namespace {

struct LINE_ITEM {
	char *ptag;
	char *pvalue;
};

}

static char* vcard_get_comma(char *pstring)
{
	char *ptoken;
	
	ptoken = strchr(pstring, ',');
	if (ptoken == nullptr)
		return NULL;
	*ptoken = '\0';
	return ptoken + 1;
}

static char* vcard_get_semicolon(char *pstring)
{
	int i;
	int tmp_len;
	
	tmp_len = strlen(pstring);
	for (i=0; i<tmp_len; i++) {
		if ('\\' == pstring[i]) {
			if ('\\' == pstring[i + 1] || ';' == pstring[i + 1] ||
				',' == pstring[i + 1]) {
				memmove(pstring + i, pstring + i + 1, tmp_len - i - 1);
				pstring[tmp_len] = '\0';
				tmp_len --;
			} else if ('n' == pstring[i + 1] || 'N' == pstring[i + 1]) {
				pstring[i] = '\r';
				pstring[i + 1] = '\n';
			}
		} else if (';' == pstring[i]) {
			pstring[i] = '\0';
			for (i += 1; i < tmp_len; ++i)
				if (pstring[i] != ' ' && pstring[i] != '\t')
					break;
			return pstring + i;
		}
	}
	return NULL;
}

static BOOL vcard_retrieve_line_item(char *pline, LINE_ITEM *pitem)
{
	BOOL b_value;
	pitem->ptag = NULL;
	pitem->pvalue = NULL;
	
	b_value = FALSE;
	while ('\0' != *pline) {
		if ((pitem->ptag == nullptr || (b_value && pitem->pvalue == nullptr)) &&
		    (*pline == ' ' || *pline == '\t')) {
			pline ++;
			continue;
		}
		if (NULL == pitem->ptag) {
			pitem->ptag = pline;
			pline ++;
			continue;
		}
		if (!b_value) {
			if (':' == *pline) {
				*pline = '\0';
				b_value = TRUE;
			}
		} else {
			if (NULL == pitem->pvalue) {
				pitem->pvalue = pline;
				break;
			}
		}
		pline ++;
	}
	return pitem->ptag != nullptr ? TRUE : false;
}

static char* vcard_get_line(char *pbuff, size_t max_length)
{
	size_t i;
	char *pnext;
	BOOL b_quoted;
	BOOL b_searched = false;
	
	b_quoted = FALSE;
	for (i=0; i<max_length; i++) {
		if ('\r' == pbuff[i]) {
			pbuff[i] = '\0';
			if (!b_searched) {
				b_searched = TRUE;
				b_quoted = strcasestr(pbuff, "QUOTED-PRINTABLE") != nullptr ? TRUE : false;
			}
			if (b_quoted) {
				if (i > 0 && pbuff[i-1] == '=') {
					memmove(pbuff + i - 1, pbuff + i, max_length - i);
					pbuff[max_length-1] = '\0';
					max_length --;
					i --;
				} else if (i + 1 < max_length && pbuff[i+1] == '\n') {
					return i + 2 < max_length ? pbuff + i + 2 : nullptr;
				} else {
					return i + 1 < max_length ? pbuff + i + 1 : nullptr;
				}
			}
			if (i + 1 < max_length && '\n' == pbuff[i + 1]) {
				pnext = pbuff + i + 2;
				if (b_quoted) {
					memmove(pbuff + i, pnext, pbuff + max_length - pnext);
					size_t bytes = pbuff + max_length - pnext;
					pbuff[i+bytes] = '\0';
					max_length -= pnext - (pbuff + i);
					continue;
				}
				if (' ' == *pnext || '\t' == *pnext) {
					for (; pnext<pbuff+max_length; pnext++) {
						if (*pnext == ' ' || *pnext == '\t')
							continue;
						break;
					}
					memmove(pbuff + i, pnext, pbuff + max_length - pnext);
					size_t bytes = pbuff + max_length - pnext;
					pbuff[i+bytes] = '\0';
					max_length -= pnext - (pbuff + i);
					continue;
				}
			} else {
				pnext = pbuff + i + 1;
				if (b_quoted) {
					memmove(pbuff + i, pnext, pbuff + max_length - pnext);
					size_t bytes = pbuff + max_length - pnext;
					pbuff[i+bytes] = '\0';
					max_length -= pnext - (pbuff + i);
					continue;
				}
				if (' ' == *pnext || '\t' == *pnext) {
					for (; pnext<pbuff+max_length; pnext++) {
						if (*pnext == ' ' || *pnext == '\t')
							continue;
						break;
					}
					memmove(pbuff + i, pnext, pbuff + max_length - pnext);
					size_t bytes = pbuff + max_length - pnext;
					pbuff[i+bytes] = '\0';
					max_length -= pnext - (pbuff + i);
					continue;
				}
			}
			return pnext;
		} else if ('\n' == pbuff[i]) {
			pbuff[i] = '\0';
			if (!b_searched) {
				b_searched = TRUE;
				b_quoted = strcasestr(pbuff, "QUOTED-PRINTABLE") != nullptr ? TRUE : false;
			}
			if (b_quoted) {
				if (i > 0 && pbuff[i-1] == '=') {
					memmove(pbuff + i - 1, pbuff + i, max_length - i);
					pbuff[max_length-1] = '\0';
					max_length --;
					i --;
				} else if (i + 1 < max_length) {
					return pbuff + i + 1;
				}
			}
			pnext = pbuff + i + 1;
			if (b_quoted) {
				memmove(pbuff + i, pnext, pbuff + max_length - pnext);
				size_t bytes = pbuff + max_length - pnext;
				pbuff[i+bytes] = '\0';
				max_length -= pnext - (pbuff + i);
				continue;
			}
			if (' ' == *pnext || '\t' == *pnext) {
				for (; pnext<pbuff+max_length; pnext++) {
					if (*pnext == ' ' || *pnext == '\t')
						continue;
					break;
				}
				memmove(pbuff + i, pnext, pbuff + max_length - pnext);
				size_t bytes = pbuff + max_length - pnext;
				pbuff[i+bytes] = '\0';
				max_length -= pnext - (pbuff + i);
				continue;
			}
			return pnext;
		}
	}
	return NULL;
}

static bool empty_line(const char *pline)
{	
	for (; *pline != '\0'; ++pline)
		if (*pline != ' ' && *pline != '\t')
			return false;
	return true;
}

static vcard_param vcard_retrieve_param(char *ptag)
{
	char *ptr;
	char *pnext;
	
	ptr = strchr(ptag, '=');
	if (ptr != nullptr)
		*ptr = '\0';
	vcard_param pvparam(ptag);
	if (ptr == nullptr)
		return pvparam;
	ptr ++;
	do {
		pnext = vcard_get_comma(ptr);
		pvparam.append_paramval(ptr);
	} while ((ptr = pnext) != NULL);
	return pvparam;
}

static vcard_line vcard_retrieve_tag(char *ptag)
{
	char *ptr;
	char *pnext;
	
	ptr = strchr(ptag, ';');
	if (ptr != nullptr)
		*ptr = '\0';
	vcard_line pvline(ptag);
	if (ptr == nullptr)
		return pvline;
	ptr ++;
	do {
		pnext = vcard_get_semicolon(ptr);
		pvline.append_param(vcard_retrieve_param(ptr));
	} while ((ptr = pnext) != NULL);
	return pvline;
}

static void vcard_retrieve_value(vcard_line *pvline, char *pvalue)
{
	char *ptr;
	char *ptr1;
	char *pnext;
	char *pnext1;
	
	ptr = pvalue;
	do {
		auto &va = pvline->append_value();
		pnext = vcard_get_semicolon(ptr);
		ptr1 = ptr;
		do {
			pnext1 = vcard_get_comma(ptr1);
			va.append_subval(ptr1);
		} while ((ptr1 = pnext1) != NULL);
	} while ((ptr = pnext) != NULL);
}

static void vcard_unescape_string(char *pstring)
{
	int i;
	int tmp_len;
	
	tmp_len = strlen(pstring);
	for (i=0; i<tmp_len; i++) {
		if (pstring[i] != '\\')
			continue;
		if ('\\' == pstring[i+1] || ';' == pstring[i+1] ||
		    ',' == pstring[i+1]) {
			memmove(pstring + i, pstring + i + 1, tmp_len - i);
			pstring[tmp_len] = '\0';
			tmp_len--;
		} else if ('n' == pstring[i+1] || 'N' == pstring[i+1]) {
			pstring[i] = '\r';
			pstring[i+1] = '\n';
		}
	}
}

static bool vcard_single_value(const char *name)
{
	static constexpr char keywords[][8] = {
		"UID", "KEY", "ADDR", "NOTE", "LOGO", "ROLE", "LABEL",
		"PHOTO", "SOUND", "TITLE", "PRODID", "VERSION",
	};
	for (const char *k : keywords)
		if (strcasecmp(name, k) == 0)
			return true;
	return false;
}

ec_error_t vcard_load_multi_from_str_move(char *in_buff,
    std::vector<vcard> &finalvec, size_t limit) try
{
	char *pline;
	char *pnext;
	BOOL b_begin;
	size_t length;
	LINE_ITEM tmp_item;
	std::vector<vcard> cardvec;
	vcard *pvcard = nullptr;

	b_begin = FALSE;
	pline = in_buff;
	length = strlen(in_buff);
	do {
		pnext = vcard_get_line(pline, length - (pline - in_buff));
		if (empty_line(pline))
			continue;
		if (!vcard_retrieve_line_item(pline, &tmp_item))
			break;
		if (!b_begin) {
			if (strcasecmp(tmp_item.ptag, "BEGIN") != 0 ||
			    tmp_item.pvalue == nullptr ||
			    strcasecmp(tmp_item.pvalue, "VCARD") != 0)
				break;
			b_begin = TRUE;
			pvcard = &cardvec.emplace_back();
			continue;
		}
		if (0 == strcasecmp(tmp_item.ptag, "END") &&
			(NULL != tmp_item.pvalue &&
			0 == strcasecmp(tmp_item.pvalue, "VCARD"))) {
			if (limit > 0 && --limit == 0)
				break;
			pvcard = nullptr;
			b_begin = false;
			continue;
		}
		auto pvline = &pvcard->append_line(vcard_retrieve_tag(tmp_item.ptag));
		if (tmp_item.pvalue == nullptr)
			continue;
		if (!vcard_single_value(pvline->name())) {
			vcard_retrieve_value(pvline, tmp_item.pvalue);
			continue;
		}
		vcard_unescape_string(tmp_item.pvalue);
		pvline->append_value(tmp_item.pvalue);
	} while ((pline = pnext) != NULL);
	finalvec = std::move(cardvec);
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ecServerOOM;
}

ec_error_t vcard::load_single_from_str_move(char *in_buff)
{
	std::vector<vcard> cardvec;
	auto ret = vcard_load_multi_from_str_move(in_buff, cardvec, 1);
	if (ret != ecSuccess)
		return ret;
	if (cardvec.size() == 0)
		return ecError;
	*this = std::move(cardvec[0]);
	return ecSuccess;
}

static void vcard_serialize_string(std::string &out,
    size_t &line_offset, const std::string_view sv)
{
	auto string = sv.data();
	for (size_t i = 0; i < sv.size(); ++i) {
		if (line_offset >= MAX_LINE) {
			out += "\r\n ";
			line_offset = 1;
		}
		if ('\\' == string[i] || ';' == string[i] || ',' == string[i]) {
			out += '\\';
			line_offset ++;
		} else if ('\r' == string[i] && '\n' == string[i + 1]) {
			out += "\\n";
			i ++;
			line_offset += 2;
			continue;
		} else if (string[i] == '\n') {
			out += "\\n";
			line_offset += 2;
			continue;
		}
		out += string[i];
		line_offset ++;
	}
}

bool vcard::serialize(std::string &out) const try
{
	BOOL need_comma;
	BOOL need_semicolon;
	
	out = "BEGIN:VCARD\r\n";
	for (const auto &line : m_lines) {
		size_t ls = 0;
		out += line.name_s();
		ls  += line.name_s().size();

		for (const auto &vparam : line.m_params) {
			out += ';';
			if (vparam.m_paramvals.size() == 0) {
				out += vparam.name_s();
				ls  += vparam.name_s().size() + 1;
				continue;
			}
			out += vparam.name_s();
			out += '=';
			ls  += vparam.name_s().size() + 2;
			need_comma = FALSE;
			for (const auto &pv : vparam.m_paramvals) {
				if (!need_comma) {
					need_comma = TRUE;
				} else {
					out += ',';
					++ls;
				}
				vcard_serialize_string(out, ls, pv);
			}
		}
		out += ':';
		++ls;
		need_semicolon = FALSE;
		for (const auto &vvalue : line.m_values) {
			if (!need_semicolon) {
				need_semicolon = TRUE;
			} else {
				out += ';';
				++ls;
			}
			bool need_comma = false;
			for (const auto &sv : vvalue.m_subvals) {
				if (!need_comma) {
					need_comma = TRUE;
				} else {
					out += ',';
					++ls;
				}
				if (!sv.empty()) {
					vcard_serialize_string(out, ls, sv);
				}
			}
		}
		out += "\r\n";
	}
	out += "END:VCARD\r\n";
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return false;
}

vcard_param &vcard_line::append_param(const char *k, const char *v)
{
	auto &param = append_param(k);
	param.append_paramval(v);
	return param;
}

vcard_value &vcard_line::append_value(const char *v)
{
	auto &value = append_value();
	value.append_subval(v);
	return value;
}

vcard_value &vcard_line::append_value(std::string &&v)
{
	auto &value = append_value();
	value.append_subval(std::move(v));
	return value;
}

const char *vcard_line::get_first_subval() const
{
	auto pvvalue = m_values.cbegin();
	if (pvvalue == m_values.cend())
		return NULL;
	return pvvalue->m_subvals.size() > 0 ? pvvalue->m_subvals[0].c_str() : nullptr;
}

vcard_line &vcard::append_line(vcard_line &&o)
{
	m_lines.push_back(std::move(o));
	auto &r = m_lines.back();
	r.m_lnum = m_lines.size();
	return r;
}

vcard_line &vcard::append_line(const char *name)
{
	auto &r = m_lines.emplace_back(name);
	r.m_lnum = m_lines.size();
	return r;
}

vcard_line &vcard::append_line(const char *name, const char *value)
{
	auto &line = append_line(name);
	line.append_value(value);
	return line;
}
