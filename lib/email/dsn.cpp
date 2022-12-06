// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gromox/dsn.hpp>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>

namespace {

struct DSN_FIELD {
	DOUBLE_LIST_NODE node;
	char *tag;
	char *value;
};

struct RCPT_DSN_FIELDS {
	DOUBLE_LIST_NODE node;
	DSN_FIELDS fields;
};

}

static void dsn_delete_rcpt_fields(DSN *, DSN_FIELDS *);

static void dsn_clear_fields(DSN_FIELDS *pfields)
{
	DSN_FIELD *pfield;
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_pop_front(pfields)) != nullptr) {
		pfield = (DSN_FIELD*)pnode->pdata;
		free(pfield->tag);
		free(pfield->value);
		free(pfield);
	}
}

DSN::DSN()
{
	auto pdsn = this;
	double_list_init(&pdsn->message_fields);
	double_list_init(&pdsn->rcpts_fields);
}

bool dsn_retrieve(DSN *pdsn, char *in_buff, size_t length)
{
	DSN_FIELDS *pfields;
	MIME_FIELD mime_field;
	size_t current_offset = 0;

	dsn_clear(pdsn);
	pfields = &pdsn->message_fields;
	while (current_offset < length) {
		if (0 == strncmp(in_buff + current_offset, "\r\n", 2)) {
			if (double_list_get_nodes_num(pfields) > 0) {
				pfields = dsn_new_rcpt_fields(pdsn);
				if (NULL == pfields) {
					dsn_clear(pdsn);
					return false;
				}
			}
			current_offset += 2;
			continue;
		}
		auto parsed_length = parse_mime_field(in_buff + current_offset,
		                     length - current_offset, &mime_field);
		current_offset += parsed_length;
		if (0 == parsed_length) {
			break;
		}
		if (!dsn_append_field(pfields, mime_field.name.c_str(),
		    mime_field.value.c_str())) {
			dsn_clear(pdsn);
			return false;
		}
	}
	if (pfields != &pdsn->message_fields &&
		0 == double_list_get_nodes_num(pfields)) {
		dsn_delete_rcpt_fields(pdsn, pfields);
	}
	return true;
}

DSN_FIELDS* dsn_get_message_fileds(DSN *pdsn)
{
	return &pdsn->message_fields;
}

DSN_FIELDS* dsn_new_rcpt_fields(DSN *pdsn)
{
	auto pfields = gromox::me_alloc<RCPT_DSN_FIELDS>();
	if (NULL == pfields) {
		return NULL;
	}
	pfields->node.pdata = pfields;
	double_list_init(&pfields->fields);
	double_list_append_as_tail(&pdsn->rcpts_fields, &pfields->node);
	return &pfields->fields;
}

static void dsn_delete_rcpt_fields(DSN *pdsn, DSN_FIELDS *pfields)
{
	DOUBLE_LIST_NODE *pnode;
	
	dsn_clear_fields(pfields);
	double_list_free(pfields);
	for (pnode=double_list_get_head(&pdsn->rcpts_fields); NULL!=pnode;
		pnode=double_list_get_after(&pdsn->rcpts_fields, pnode)) {
		if (pfields == &((RCPT_DSN_FIELDS*)pnode->pdata)->fields) {
			double_list_remove(&pdsn->rcpts_fields, pnode);
			free(pnode->pdata);
			break;
		}
	}
}

bool dsn_append_field(DSN_FIELDS *pfields, const char *tag, const char *value)
{
	auto pfield = gromox::me_alloc<DSN_FIELD>();
	if (NULL == pfield) {
		return false;
	}
	pfield->node.pdata = pfield;
	pfield->tag = strdup(tag);
	if (NULL == pfield->tag) {
		free(pfield);
		return false;
	}
	pfield->value = strdup(value);
	if (NULL == pfield->value) {
		free(pfield->tag);
		free(pfield);
		return false;
	}
	double_list_append_as_tail(pfields, &pfield->node);
	return true;
}

bool dsn_enum_rcpts_fields(DSN *pdsn, RCPTS_FIELDS_ENUM enum_func, void *pparam)
{
	DOUBLE_LIST_NODE *pnode;
	RCPT_DSN_FIELDS *pfields;
	
	for (pnode=double_list_get_head(&pdsn->rcpts_fields); NULL!=pnode;
		pnode=double_list_get_after(&pdsn->rcpts_fields, pnode)) {
		pfields = (RCPT_DSN_FIELDS*)pnode->pdata;
		if (!enum_func(&pfields->fields, pparam))
			return false;
	}
	return true;
}

bool dsn_enum_fields(DSN_FIELDS *pfields, DSN_FIELDS_ENUM enum_func,
    void *pparam)
{
	DSN_FIELD *pfield;
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(pfields); NULL!=pnode;
		pnode=double_list_get_after(pfields, pnode)) {
		pfield = (DSN_FIELD*)pnode->pdata;
		if (!enum_func(pfield->tag, pfield->value, pparam))
			return false;
	}
	return true;
}

bool dsn_serialize(DSN *pdsn, char *out_buff, size_t max_length)
{
	size_t offset;
	DSN_FIELD *pfield;
	DSN_FIELDS *pfields;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	
	offset = 0;
	for (pnode=double_list_get_head(&pdsn->message_fields); NULL!=pnode;
		pnode=double_list_get_after(&pdsn->message_fields, pnode)) {
		pfield = (DSN_FIELD*)pnode->pdata;
		offset += gx_snprintf(out_buff + offset, max_length - offset,
					"%s: %s\r\n", pfield->tag, pfield->value);
	}
	if (offset + 2 >= max_length - 1) {
		return false;
	}
	out_buff[offset] = '\r';
	offset ++;
	out_buff[offset] = '\n';
	offset ++;
	out_buff[offset] = '\0';
	for (pnode1=double_list_get_head(&pdsn->rcpts_fields); NULL!=pnode1;
		pnode1=double_list_get_after(&pdsn->rcpts_fields, pnode1)) {
		pfields = &((RCPT_DSN_FIELDS*)pnode1->pdata)->fields;
		for (pnode=double_list_get_head(pfields); NULL!=pnode;
			pnode=double_list_get_after(pfields, pnode)) {
			pfield = (DSN_FIELD*)pnode->pdata;
			offset += gx_snprintf(out_buff + offset, max_length - offset,
						"%s: %s\r\n", pfield->tag, pfield->value);
		}
		if (offset + 2 >= max_length - 1) {
			return false;
		}
		out_buff[offset] = '\r';
		offset ++;
		out_buff[offset] = '\n';
		offset ++;
		out_buff[offset] = '\0';
	}
	return true;
}

void dsn_clear(DSN *pdsn)
{
	DOUBLE_LIST_NODE *pnode;
	
	dsn_clear_fields(&pdsn->message_fields);
	while ((pnode = double_list_pop_front(&pdsn->rcpts_fields)) != nullptr) {
		dsn_clear_fields(&((RCPT_DSN_FIELDS*)pnode->pdata)->fields);
		double_list_free(&((RCPT_DSN_FIELDS*)pnode->pdata)->fields);
		free(pnode->pdata);
	}
}

DSN::~DSN()
{
	auto pdsn = this;
	dsn_clear(pdsn);
	double_list_free(&pdsn->message_fields);
	double_list_free(&pdsn->rcpts_fields);
}
