#pragma once
#include <gromox/defs.h>
#include <gromox/mime.hpp>
#include <gromox/stream.hpp>
#include <gromox/mime_pool.hpp>
#include <gromox/simple_tree.hpp>
#define	MIME_INSERT_BEFORE	SIMPLE_TREE_INSERT_BEFORE
#define MIME_INSERT_AFTER	SIMPLE_TREE_INSERT_AFTER
#define MIME_ADD_FIRST		SIMPLE_TREE_ADD_FIRST
#define	MIME_ADD_LAST		SIMPLE_TREE_ADD_LAST

using MAIL_MIME_ENUM = void (*)(MIME *, void*);

struct GX_EXPORT MAIL {
	MAIL() = default;
	MAIL(MIME_POOL *);
	MAIL(MAIL &&) = delete;
	~MAIL();
	MAIL &operator=(MAIL &&);

	void clear();
	BOOL retrieve(char *in_buff, size_t length);
	BOOL serialize(STREAM *);
	BOOL to_file(int fd);
	BOOL to_ssl(SSL *ssl);
	BOOL check_dot();
	BOOL transfer_dot(MAIL *dst);
	ssize_t get_length();
	MIME *add_head();
	MIME *get_head();
	BOOL get_charset(char *out);
	int get_digest(size_t *offset, char *buf, int len);
	MIME *add_child(MIME *base, int opt);
	void enum_mime(MAIL_MIME_ENUM, void *);
	BOOL dup(MAIL *dst);

	SIMPLE_TREE tree{};
	MIME_POOL *pmime_pool = nullptr;
	char *buffer = nullptr;
};
