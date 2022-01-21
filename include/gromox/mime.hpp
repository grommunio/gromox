#pragma once
#include <gromox/stream.hpp>
#include <gromox/mem_file.hpp>
#include <gromox/simple_tree.hpp>
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

using MIME_FIELD_ENUM = BOOL (*)(const char *, char *, void *);

struct MAIL;
struct GX_EXPORT MIME {
	BOOL retrieve(MIME *parent, char *in_buf, size_t len);
	void clear();
	BOOL write_content(const char *content, size_t len, int encoding_type);
	BOOL write_mail(MAIL *);
	BOOL read_head(char *out_buf, size_t *len);
	BOOL read_content(char *out_buf, size_t *len);
	BOOL set_content_type(const char *);
	BOOL enum_field(MIME_FIELD_ENUM, void *);
	BOOL get_field(const char *tag, char *value, int len);
	int get_field_num(const char *tag);
	BOOL search_field(const char *tag, int order, char *value, int len);
	BOOL set_field(const char *tag, const char *value);
	BOOL append_field(const char *tag, const char *value);
	BOOL remove_field(const char *tag);
	BOOL get_content_param(const char *tag, char *value, int len);
	BOOL set_content_param(const char *tag, const char *value);
	ssize_t get_mimes_digest(const char *, size_t *, size_t *, char *, size_t);
	ssize_t get_structure_digest(const char *, size_t *, size_t *, char *, size_t);
	inline size_t get_children_num() const { return simple_tree_node_get_children_num(&node); }

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
};

void mime_init(MIME *pmime, LIB_BUFFER *palloc);
void mime_free(MIME *pmime);
BOOL mime_serialize(MIME *pmime, STREAM *pstream);
BOOL mime_to_file(MIME *pmime, int fd);
BOOL mime_to_ssl(MIME *pmime, SSL *ssl);
BOOL mime_check_dot(MIME *pmime);
extern ssize_t mime_get_length(MIME *);
BOOL mime_get_filename(MIME *pmime, char *file_name);
MIME* mime_get_child(MIME *pmime);
MIME* mime_get_parent(MIME *pmime);
extern MIME *mime_get_sibling(MIME *);
