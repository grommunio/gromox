// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
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
			for (i+=1; i<tmp_len; i++) {
				if (' ' != pstring[i] && '\t' != pstring[i]) {
					break;
				}
			}
			return pstring + i;
		}
	}
	return NULL;
}

vcard::vcard()
{
	double_list_init(&line_list);
}

vcard::vcard(vcard &&o) :
	line_list(o.line_list)
{
	o.line_list = {};
}

vcard &vcard::operator=(vcard &&o)
{
	clear();
	double_list_free(&line_list);
	line_list = o.line_list;
	o.line_list = {};
	return *this;
}

static void vcard_free_param(VCARD_PARAM *pvparam)
{
	DOUBLE_LIST_NODE *pnode;
	
	if (NULL == pvparam->pparamval_list) {
		free(pvparam);
		return;
	}
	while ((pnode = double_list_pop_front(pvparam->pparamval_list)) != nullptr) {
		free(pnode->pdata);
		free(pnode);
	}
	double_list_free(pvparam->pparamval_list);
	free(pvparam->pparamval_list);
	free(pvparam);
}

static void vcard_free_value(VCARD_VALUE *pvvalue)
{
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_pop_front(&pvvalue->subval_list)) != nullptr) {
		if (NULL != pnode->pdata) {
			free(pnode->pdata);
		}
		free(pnode);
	}
	double_list_free(&pvvalue->subval_list);
	free(pvvalue);
}

static void vcard_free_line(VCARD_LINE *pvline)
{
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_pop_front(&pvline->param_list)) != nullptr)
		vcard_free_param(static_cast<VCARD_PARAM *>(pnode->pdata));
	double_list_free(&pvline->param_list);
	while ((pnode = double_list_pop_front(&pvline->value_list)) != nullptr)
		vcard_free_value(static_cast<VCARD_VALUE *>(pnode->pdata));
	double_list_free(&pvline->value_list);
	free(pvline);
}

vcard::~vcard()
{
	clear();
	double_list_free(&line_list);
}

void vcard::clear()
{
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_pop_front(&line_list)) != nullptr)
		vcard_free_line(static_cast<VCARD_LINE *>(pnode->pdata));
	double_list_free(&line_list);
	double_list_init(&line_list);
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
				if (NULL != strcasestr(pbuff, "QUOTED-PRINTABLE")) {
					b_quoted = TRUE;
				} else {
					b_quoted = FALSE;
				}
			}
			if (b_quoted) {
				if ('=' == pbuff[i - 1]) {
					memmove(pbuff + i - 1, pbuff + i, max_length - i);
					pbuff[max_length-1] = '\0';
					max_length --;
					i --;
				} else {
					if ('\n' == pbuff[i + 1]) {
						if (i + 2 < max_length) {
							return pbuff + i + 2;
						}
					} else {
						if (i + 1 < max_length) {
							return pbuff + i + 1;
						}
					}
					return NULL;
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
						if (' ' == *pnext || '\t' == *pnext) {
							continue;
						}
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
						if (' ' == *pnext || '\t' == *pnext) {
							continue;
						}
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
				if (NULL != strcasestr(pbuff, "QUOTED-PRINTABLE")) {
					b_quoted = TRUE;
				} else {
					b_quoted = FALSE;
				}
			}
			if (b_quoted) {
				if ('=' == pbuff[i - 1]) {
					memmove(pbuff + i - 1, pbuff + i, max_length - i);
					pbuff[max_length-1] = '\0';
					max_length --;
					i --;
				} else {
					if (i + 1 < max_length) {
						return pbuff + i + 1;
					}
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
					if (' ' == *pnext || '\t' == *pnext) {
						continue;
					}
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

static BOOL vcard_check_empty_line(const char *pline)
{	
	for (; *pline != '\0'; ++pline)
		if (' ' != *pline && '\t' != *pline) {
			return FALSE;
		}
	return TRUE;
}

static VCARD_PARAM* vcard_retrieve_param(char *ptag)
{
	char *ptr;
	char *pnext;
	VCARD_PARAM *pvparam;
	
	ptr = strchr(ptag, '=');
	if (NULL != ptr) {
		*ptr = '\0';
	}
	pvparam = vcard_new_param(ptag);
	if (pvparam == nullptr)
		return NULL;
	if (ptr == nullptr)
		return pvparam;
	ptr ++;
	do {
		pnext = vcard_get_comma(ptr);
		auto ret = pvparam->append_paramval(ptr);
		if (ret != ecSuccess) {
			vcard_free_param(pvparam);
			return nullptr;
		}
	} while ((ptr = pnext) != NULL);
	return pvparam;
}

static VCARD_LINE* vcard_retrieve_tag(char *ptag)
{
	char *ptr;
	char *pnext;
	VCARD_LINE *pvline;
	VCARD_PARAM *pvparam;
	
	ptr = strchr(ptag, ';');
	if (NULL != ptr) {
		*ptr = '\0';
	}
	pvline = vcard_new_line(ptag);
	if (pvline == nullptr)
		return NULL;
	if (ptr == nullptr)
		return pvline;
	ptr ++;
	do {
		pnext = vcard_get_semicolon(ptr);
		pvparam = vcard_retrieve_param(ptr);
		if (pvparam == nullptr)
			return nullptr;
		auto ret = pvline->append_param(pvparam);
		if (ret != ecSuccess)
			return nullptr;
	} while ((ptr = pnext) != NULL);
	return pvline;
}

static ec_error_t vcard_retrieve_value(VCARD_LINE *pvline, char *pvalue)
{
	char *ptr;
	char *ptr1;
	char *pnext;
	char *pnext1;
	VCARD_VALUE *pvvalue;
	
	ptr = pvalue;
	do {
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return ecServerOOM;
		auto ret = pvline->append_value(pvvalue);
		if (ret != ecSuccess)
			return ret;
		pnext = vcard_get_semicolon(ptr);
		ptr1 = ptr;
		do {
			pnext1 = vcard_get_comma(ptr1);
			if ('\0' == *ptr1) {
				ret = pvvalue->append_subval(nullptr);
				if (ret != ecSuccess)
					return ret;
			} else {
				ret = pvvalue->append_subval(ptr1);
				if (ret != ecSuccess)
					return ret;
			}
		} while ((ptr1 = pnext1) != NULL);
	} while ((ptr = pnext) != NULL);
	return ecSuccess;
}

static void vcard_unescape_string(char *pstring)
{
	int i;
	int tmp_len;
	
	tmp_len = strlen(pstring);
	for (i=0; i<tmp_len; i++) {
		if ('\\' == pstring[i]) {
			if ('\\' == pstring[i + 1] || ';' == pstring[i + 1] ||
				',' == pstring[i + 1]) {
				memmove(pstring + i, pstring + i + 1, tmp_len - i);
				pstring[tmp_len] = '\0';
				tmp_len --;
			} else if ('n' == pstring[i + 1] || 'N' == pstring[i + 1]) {
				pstring[i] = '\r';
				pstring[i + 1] = '\n';
			}
		}
	}
}

static bool vcard_std_keyword(const char *name)
{
	static constexpr char keywords[][8] = {
		"ORG", "UID", "KEY", "ADDR", "NOTE", "LOGO", "ROLE", "LABEL",
		"PHOTO", "SOUND", "TITLE", "PRODID", "VERSION",
	};
	for (const char *k : keywords)
		if (strcasecmp(name, k) == 0)
			return true;
	return false;
}

ec_error_t vcard_retrieve_multi(char *in_buff, std::vector<vcard> &finalvec,
    size_t limit) try
{
	char *pline;
	char *pnext;
	BOOL b_begin;
	size_t length;
	VCARD_LINE *pvline;
	LINE_ITEM tmp_item;
	VCARD_VALUE *pvvalue;
	std::vector<vcard> cardvec;
	vcard *pvcard = nullptr;

	b_begin = FALSE;
	pline = in_buff;
	length = strlen(in_buff);
	do {
		pnext = vcard_get_line(pline, length - (pline - in_buff));
		if (vcard_check_empty_line(pline))
			continue;
		if (!vcard_retrieve_line_item(pline, &tmp_item))
			break;
		if (!b_begin) {
			if (0 == strcasecmp(tmp_item.ptag, "BEGIN") &&
				(NULL != tmp_item.pvalue &&
				0 == strcasecmp(tmp_item.pvalue, "VCARD"))) {
				b_begin = TRUE;
				pvcard = &cardvec.emplace_back();
				continue;
			} else {
				break;
			}
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
		pvline = vcard_retrieve_tag(tmp_item.ptag);
		if (pvline == nullptr)
			break;
		auto ret = pvcard->append_line2(pvline);
		if (ret != ecSuccess)
			return ret;
		if (NULL != tmp_item.pvalue) {
			if (vcard_std_keyword(pvline->name)) {
				pvvalue = vcard_new_value();
				if (pvvalue == nullptr)
					return ecServerOOM;
				ret = pvline->append_value(pvvalue);
				if (ret != ecSuccess)
					return ret;
				vcard_unescape_string(tmp_item.pvalue);
				ret = pvvalue->append_subval(tmp_item.pvalue);
				if (ret != ecSuccess)
					return ret;
			} else {
				auto rv = vcard_retrieve_value(pvline, tmp_item.pvalue);
				if (rv != ecSuccess)
					break;
			}
		}
		
	} while ((pline = pnext) != NULL);
	finalvec = std::move(cardvec);
	return ecSuccess;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-2042: ENOMEM\n");
	return ecServerOOM;
}

ec_error_t vcard::retrieve_single(char *in_buff)
{
	std::vector<vcard> cardvec;
	auto ret = vcard_retrieve_multi(in_buff, cardvec, 1);
	if (ret != ecSuccess)
		return ret;
	if (cardvec.size() == 0)
		return ecError;
	*this = std::move(cardvec[0]);
	return ecSuccess;
}
static size_t vcard_serialize_string(char *pbuff,
	size_t max_length, int line_offset, const char *string)
{
	size_t i;
	size_t offset;
	size_t tmp_len;
	
	if (line_offset >= MAX_LINE) {
		line_offset %= MAX_LINE;
	}
	offset = 0;
	tmp_len = strlen(string);
	for (i=0; i<tmp_len; i++) {
		if (offset >= max_length) {
			return offset;
		}
		if (line_offset >= MAX_LINE) {
			if (offset + 3 >= max_length) {
				return max_length;
			}
			memcpy(pbuff + offset, "\r\n ", 3);
			offset += 3;
			line_offset = 0;
		}
		if ('\\' == string[i] || ';' == string[i] || ',' == string[i]) {
			if (offset + 1 >= max_length) {
				return max_length;
			}
			pbuff[offset] = '\\';
			offset ++;
			if (line_offset >= 0) {
				line_offset ++;
			}
		} else if ('\r' == string[i] && '\n' == string[i + 1]) {
			if (offset + 1 >= max_length) {
				return max_length;
			}
			pbuff[offset] = '\\';
			offset ++;
			pbuff[offset] = 'n';
			offset ++;
			i ++;
			if (line_offset >= 0) {
				line_offset += 2;
			}
			continue;
		}
		pbuff[offset] = string[i];
		offset ++;
		if (line_offset >= 0) {
			line_offset ++;
		}
	}
	return offset;
}

BOOL vcard::serialize(char *out_buff, size_t max_length)
{
	auto pvcard = this;
	size_t offset;
	BOOL need_comma;
	size_t line_begin;
	VCARD_LINE *pvline;
	BOOL need_semicolon;
	VCARD_PARAM *pvparam;
	VCARD_VALUE *pvvalue;
	DOUBLE_LIST_NODE *pnode1;
	DOUBLE_LIST_NODE *pnode2;
	
	if (max_length <= 13) {
		return FALSE;
	}
	memcpy(out_buff, "BEGIN:VCARD\r\n", 13);
	offset = 13;
	for (auto pnode = double_list_get_head(&pvcard->line_list); pnode != nullptr;
	     pnode = double_list_get_after(&pvcard->line_list, pnode)) {
		line_begin = offset;
		pvline = (VCARD_LINE*)pnode->pdata;
		offset += gx_snprintf(out_buff + offset,
			max_length - offset, "%s", pvline->name);
		if (offset >= max_length) {
			return FALSE;
		}
		for (pnode1=double_list_get_head(&pvline->param_list); NULL!=pnode1;
			pnode1=double_list_get_after(&pvline->param_list, pnode1)) {
			pvparam = (VCARD_PARAM*)pnode1->pdata;
			if (offset + 1 >= max_length) {
				return FALSE;
			}
			out_buff[offset] = ';';
			offset ++;
			if (NULL == pvparam->pparamval_list) {
				offset += gx_snprintf(out_buff + offset,
					max_length - offset, "%s", pvparam->name);
				if (offset >= max_length) {
					return FALSE;
				}
				continue;
			}
			offset += gx_snprintf(out_buff + offset,
				max_length - offset, "%s=", pvparam->name);
			if (offset >= max_length) {
				return FALSE;
			}
			need_comma = FALSE;
			for (pnode2=double_list_get_head(pvparam->pparamval_list);
				NULL!=pnode2; pnode2=double_list_get_after(
				pvparam->pparamval_list, pnode2)) {
				if (!need_comma) {
					need_comma = TRUE;
				} else {
					if (offset + 1 >= max_length) {
						return FALSE;
					}
					out_buff[offset] = ',';
					offset ++;
				}
				offset += vcard_serialize_string(out_buff + offset,
				          max_length - offset, -1, static_cast<char *>(pnode2->pdata));
				if (offset >= max_length) {
					return FALSE;
				}
			}
		}
		out_buff[offset] = ':';
		offset ++;
		if (offset >= max_length) {
			return FALSE;
		}
		need_semicolon = FALSE;
		for (pnode1=double_list_get_head(&pvline->value_list); NULL!=pnode1;
			pnode1=double_list_get_after(&pvline->value_list, pnode1)) {
			pvvalue = (VCARD_VALUE*)pnode1->pdata;
			if (!need_semicolon) {
				need_semicolon = TRUE;
			} else {
				if (offset + 1 >= max_length) {
					return FALSE;
				}
				out_buff[offset] = ';';
				offset ++;
			}
			need_comma = FALSE;
			for (pnode2=double_list_get_head(&pvvalue->subval_list);
				NULL!=pnode2; pnode2=double_list_get_after(
				&pvvalue->subval_list, pnode2)) {
				if (!need_comma) {
					need_comma = TRUE;
				} else {
					if (offset + 1 >= max_length) {
						return FALSE;
					}
					out_buff[offset] = ',';
					offset ++;
				}
				if (NULL != pnode2->pdata) {
					offset += vcard_serialize_string(out_buff + offset,
					          max_length - offset, offset - line_begin,
					          static_cast<char *>(pnode2->pdata));
					if (offset >= max_length) {
						return FALSE;
					}
				}
			}
		}
		if (offset + 2 >= max_length) {
			return FALSE;
		}
		out_buff[offset] = '\r';
		offset ++;
		out_buff[offset] = '\n';
		offset ++;
	}
	if (offset + 12 > max_length) {
		return FALSE;
	}
	memcpy(out_buff + offset, "END:VCARD\r\n", 12);
	return TRUE;
}

VCARD_LINE* vcard_new_line(const char *name)
{
	auto pvline = me_alloc<VCARD_LINE>();
	if (pvline == nullptr)
		return NULL;
	pvline->node.pdata = pvline;
	gx_strlcpy(pvline->name, name, GX_ARRAY_SIZE(pvline->name));
	double_list_init(&pvline->param_list);
	double_list_init(&pvline->value_list);
	return pvline;
}

ec_error_t vcard::append_line2(VCARD_LINE *pvline)
{
	double_list_append_as_tail(&line_list, &pvline->node);
	return ecSuccess;
}

VCARD_PARAM* vcard_new_param(const char*name)
{
	auto pvparam = me_alloc<VCARD_PARAM>();
	if (pvparam == nullptr)
		return NULL;
	pvparam->node.pdata = pvparam;
	gx_strlcpy(pvparam->name, name, GX_ARRAY_SIZE(pvparam->name));
	pvparam->pparamval_list = NULL;
	return pvparam;
}

ec_error_t vcard_param::append_paramval(const char *paramval)
{
	auto pvparam = this;
	BOOL b_list;
	
	if (NULL == pvparam->pparamval_list) {
		b_list = TRUE;
		pvparam->pparamval_list = me_alloc<DOUBLE_LIST>();
		if (pvparam->pparamval_list == nullptr)
			return ecServerOOM;
		double_list_init(pvparam->pparamval_list);
	} else {
		b_list = FALSE;
	}
	auto pnode = me_alloc<DOUBLE_LIST_NODE>();
	if (NULL == pnode) {
		if (b_list) {
			double_list_free(pvparam->pparamval_list);
			free(pvparam->pparamval_list);
			pvparam->pparamval_list = NULL;
		}
		return ecServerOOM;
	}
	pnode->pdata = strdup(paramval);
	if (NULL == pnode->pdata) {
		free(pnode);
		if (b_list) {
			double_list_free(pvparam->pparamval_list);
			free(pvparam->pparamval_list);
			pvparam->pparamval_list = NULL;
		}
		return ecServerOOM;
	}
	double_list_append_as_tail(pvparam->pparamval_list, pnode);
	return ecSuccess;
}

ec_error_t vcard_line::append_param(VCARD_PARAM *pvparam)
{
	double_list_append_as_tail(&param_list, &pvparam->node);
	return ecSuccess;
}

VCARD_VALUE* vcard_new_value()
{
	auto pvvalue = me_alloc<VCARD_VALUE>();
	if (pvvalue == nullptr)
		return NULL;
	pvvalue->node.pdata = pvvalue;
	double_list_init(&pvvalue->subval_list);
	return pvvalue;
}

ec_error_t vcard_value::append_subval(const char *subval)
{
	auto pvvalue = this;
	auto pnode = me_alloc<DOUBLE_LIST_NODE>();
	if (pnode == nullptr)
		return ecServerOOM;
	if (NULL != subval) {
		pnode->pdata = strdup(subval);
		if (NULL == pnode->pdata) {
			free(pnode);
			return ecServerOOM;
		}
	} else {
		pnode->pdata = NULL;
	}
	double_list_append_as_tail(&pvvalue->subval_list, pnode);
	return ecSuccess;
}

ec_error_t vcard_line::append_value(VCARD_VALUE *pvvalue)
{
	double_list_append_as_tail(&value_list, &pvvalue->node);
	return ecSuccess;
}

const char *vcard_line::get_first_subval() const
{
	auto pnode = double_list_get_head(&value_list);
	if (pnode == nullptr)
		return NULL;
	auto pvvalue = static_cast<const VCARD_VALUE *>(pnode->pdata);
	auto pnode1 = double_list_get_head(&pvvalue->subval_list);
	if (pnode1 == nullptr)
		return NULL;
	return static_cast<const char *>(pnode1->pdata);
}

ec_error_t vcard::append_line2(const char *name, const char *value)
{
	VCARD_LINE *pvline;
	VCARD_VALUE *pvvalue;
	
	pvline = vcard_new_line(name);
	if (pvline == nullptr)
		return ecServerOOM;
	pvvalue = vcard_new_value();
	if (NULL == pvvalue) {
		vcard_free_line(pvline);
		return ecServerOOM;
	}
	auto ret = pvline->append_value(pvvalue);
	if (ret != ecSuccess) {
		vcard_free_line(pvline);
		return ret;
	}
	ret = pvvalue->append_subval(value);
	if (ret != ecSuccess) {
		vcard_free_line(pvline);
		return ret;
	}
	ret = append_line2(std::move(pvline));
	if (ret != ecSuccess) {
		vcard_free_line(pvline);
		return ret;
	}
	return ecSuccess;
}
