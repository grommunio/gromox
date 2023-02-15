#pragma once
#include <openssl/ssl.h>
#include <gromox/mem_file.hpp>
#include <gromox/simple_tree.hpp>
#include <gromox/stream.hpp>
#include <gromox/util.hpp>
#define VALUE_LEN	256

enum class mime_type {
	none, single, multiple,
};

enum class mime_encoding {
	none, base64, qp, uuencode, automatic, unknown,
};

using MIME_FIELD_ENUM = BOOL (*)(const char *, const char *, void *);

struct LIB_BUFFER;
struct MAIL;
struct GX_EXPORT MIME {
	MIME(alloc_limiter<file_block> *);
	NOMOVE(MIME);
	~MIME();

	bool retrieve(MIME *parent, char *in_buf, size_t len);
	void clear();
	bool write_content(const char *content, size_t len, enum mime_encoding);
	bool write_mail(MAIL *);
	bool read_head(char *out_buf, size_t *len) const;
	bool read_content(char *out_buf, size_t *len) const;
	bool set_content_type(const char *);
	bool enum_field(MIME_FIELD_ENUM, void *) const;
	bool get_field(const char *tag, char *value, int len) const;
	int get_field_num(const char *tag) const;
	bool search_field(const char *tag, int order, char *value, int len) const;
	bool set_field(const char *tag, const char *value);
	bool append_field(const char *tag, const char *value);
	bool remove_field(const char *tag);
	bool get_content_param(const char *tag, char *value, int len) const;
	bool set_content_param(const char *tag, const char *value);
	ssize_t get_mimes_digest(const char *, size_t *, size_t *, char *, size_t) const;
	ssize_t get_structure_digest(const char *, size_t *, size_t *, char *, size_t) const;
	bool serialize(STREAM *) const;
	bool to_file(int fd) const;
	bool to_tls(SSL *) const;
	bool check_dot() const;
	ssize_t get_length() const;
	bool get_filename(char *file_name, size_t) const;
	MIME *get_child();
	const MIME *get_child() const;
	MIME *get_parent();
	const MIME *get_parent() const;
	MIME *get_sibling();
	const MIME *get_sibling() const;
	inline size_t get_children_num() const { return node.get_children_num(); }

	SIMPLE_TREE_NODE node{};
	enum mime_type mime_type = mime_type::none;
	int boundary_len = 0;
	char content_type[VALUE_LEN]{}, boundary_string[VALUE_LEN]{};
	MEM_FILE f_type_params{}, f_other_fields{};
	BOOL head_touched = false, content_touched = false;
	char *head_begin = nullptr;
	char *content_begin = nullptr;
	size_t head_length = 0, content_length = 0;
	char *first_boundary = nullptr, *last_boundary = nullptr;
};
