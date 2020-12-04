#pragma once
#ifndef __cplusplus
#	include <stdbool.h>
#endif
#include "stream.h"
#include "mem_file.h"
#include "simple_tree.h"
#include <openssl/ssl.h>

#define VALUE_LEN	256

enum{
	NONE_MIME = 0,
	SINGLE_MIME,
	MULTIPLE_MIME
};

enum{
	MIME_ENCODING_NONE = 0,
	MIME_ENCODING_BASE64,
	MIME_ENCODING_QP,
	MIME_ENCODING_UUENCODE,
	MIME_ENCODING_UNKNOWN
};

typedef BOOL (*MIME_FIELD_ENUM)(const char*, char*, void*);

typedef struct _MIME {
	SIMPLE_TREE_NODE node;
	int			mime_type;
	char 		content_type[VALUE_LEN];
	char		boundary_string[VALUE_LEN];
	int			boundary_len;
	MEM_FILE	f_type_params;
	MEM_FILE	f_other_fields;
	BOOL		head_touched;
	BOOL		content_touched;
	char		*head_begin;
	size_t		head_length;
	char		*content_begin;
	size_t		content_length;
	char		*first_boundary;
	char		*last_boundary;
} MIME;

struct _MAIL;

#ifdef __cplusplus
extern "C" {
#endif

extern bool mail_set_header(struct _MAIL *, const char *hdr, const char *val);
void mime_init(MIME *pmime, LIB_BUFFER *palloc);

void mime_free(MIME *pmime);

BOOL mime_retrieve(MIME *pmime_parent,
	MIME *pmime, char* in_buff, size_t length);

void mime_clear(MIME *pmime);

BOOL mime_clear_content(MIME *pmime);
extern BOOL mime_write_content(MIME *pmime, const char *pcontent, size_t length,
	int encoding_type);

BOOL mime_write_mail(MIME *pmime, struct _MAIL *pmail);

BOOL mime_read_head(MIME *pmime, char *out_buff, size_t *plength);

BOOL mime_read_content(MIME *pmime, char *out_buff, size_t *plength);

BOOL mime_set_content_type(MIME *pmime, const char *content_type);

const char* mime_get_content_type(MIME *pmime);

BOOL mime_enum_field(MIME *pmime, MIME_FIELD_ENUM enum_func, void *pparam);

BOOL mime_get_field(MIME *pmime, const char *tag, char *value, int length);

int mime_get_field_num(MIME *pmime, const char *tag);

BOOL mime_search_field(MIME *pmime, const char *tag, int order, char *value,
	int length);

BOOL mime_set_field(MIME *pmime, const char *tag, const char *value);

BOOL mime_append_field(MIME *pmime, const char *tag, const char *value);

BOOL mime_remove_field(MIME *pmime, const char *tag);

BOOL mime_get_content_param(MIME *pmime, const char *tag, char *value, 
	int length);

BOOL mime_set_content_param(MIME *pmime, const char *tag, const char *value);

int mime_get_mimes_digest(MIME *pmime, const char* id_string,
	size_t *poffset, int *pcount, char *pbuff, int length);

int mime_get_structure_digest(MIME *pmime, const char* id_string,
	size_t *poffset, int *pcount, char *pbuff, int length);

BOOL mime_serialize(MIME *pmime, STREAM *pstream);

BOOL mime_to_file(MIME *pmime, int fd);

BOOL mime_to_ssl(MIME *pmime, SSL *ssl);

BOOL mime_check_dot(MIME *pmime);

long mime_get_length(MIME *pmime);

int mime_get_type(MIME *pmime);

BOOL mime_get_filename(MIME *pmime, char *file_name);

const char* mime_get_boundary(MIME *pmime);

void mime_copy(MIME *pmime_src, MIME *pmime_dst);

MIME* mime_get_child(MIME *pmime);

MIME* mime_get_parent(MIME *pmime);
extern MIME *mime_get_sibling(MIME *);
size_t mime_get_children_num(MIME *pmime);

#ifdef __cplusplus
}
#endif
