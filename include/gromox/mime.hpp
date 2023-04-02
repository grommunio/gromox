#pragma once
#include <vector>
#include <json/value.h>
#include <openssl/ssl.h>
#include <gromox/mail_func.hpp>
#include <gromox/simple_tree.hpp>
#include <gromox/stream.hpp>
#include <gromox/util.hpp>
#define VALUE_LEN	256

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

	using write_func = ssize_t (*)(void *, const void *, size_t);
	bool load_from_str_move(MIME *parent, char *in_buf, size_t len);
	void clear();
	bool write_content(const char *content, size_t len, enum mime_encoding);
	bool write_mail(MAIL *);
	bool read_head(char *out_buf, size_t *len) const;
	bool read_content(char *out_buf, size_t *len) const;
	bool set_content_type(const char *);
	bool enum_field(MIME_FIELD_ENUM, void *) const;
	bool get_field(const char *tag, char *value, size_t len) const;
	int get_field_num(const char *tag) const;
	bool search_field(const char *tag, int order, char *value, size_t len) const;
	bool set_field(const char *tag, const char *value);
	bool append_field(const char *tag, const char *value);
	bool remove_field(const char *tag);
	bool get_content_param(const char *tag, char *value, size_t len) const;
	bool set_content_param(const char *tag, const char *value);
	int get_mimes_digest(const char *, size_t *, Json::Value &) const;
	int get_structure_digest(const char *, size_t *, Json::Value &) const;
	bool serialize(STREAM *) const;
	bool emit(write_func, void *) const;
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
	std::vector<kvpair> f_type_params;
	/* For @f_other_fields, we want (need?) some container that retains insertion order. */
	std::vector<MIME_FIELD> f_other_fields;
	BOOL head_touched = false;
	char *head_begin = nullptr;
	std::unique_ptr<char[], gromox::stdlib_delete> content_buf;
	char *content_begin = nullptr;
	size_t head_length = 0, content_length = 0;
	char *first_boundary = nullptr, *last_boundary = nullptr;
};
