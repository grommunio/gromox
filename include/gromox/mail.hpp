#pragma once
#include <memory>
#include <gromox/defs.h>
#include <gromox/mime.hpp>
#include <gromox/simple_tree.hpp>
#include <gromox/stream.hpp>
#define	MIME_INSERT_BEFORE	SIMPLE_TREE_INSERT_BEFORE
#define MIME_INSERT_AFTER	SIMPLE_TREE_INSERT_AFTER
#define MIME_ADD_FIRST		SIMPLE_TREE_ADD_FIRST
#define	MIME_ADD_LAST		SIMPLE_TREE_ADD_LAST

using MAIL_MIME_ENUM = void (*)(MIME *, void*);

struct MIME_POOL;
struct GX_EXPORT MAIL {
	/*
	 * Default-construction is only allowed for simplifying initialization.
	 * When used, you must move-assign a new MAIL obj with proper pool ptr
	 * when actually using a MAIL object.
	 */
	MAIL() = default;
	MAIL(std::shared_ptr<MIME_POOL>);
	MAIL(MAIL &&) = delete;
	~MAIL();
	MAIL &operator=(MAIL &&);

	void clear();
	bool retrieve(char *in_buff, size_t length);
	bool serialize(STREAM *);
	bool to_file(int fd);
	bool to_tls(SSL *);
	bool check_dot();
	bool transfer_dot(MAIL *dst);
	ssize_t get_length();
	MIME *add_head();
	MIME *get_head();
	bool get_charset(char *out);
	int get_digest(size_t *offset, char *buf, int len);
	MIME *add_child(MIME *base, int opt);
	void enum_mime(MAIL_MIME_ENUM, void *);
	bool dup(MAIL *dst);
	bool set_header(const char *hdr, const char *val);

	SIMPLE_TREE tree{};
	std::shared_ptr<MIME_POOL> pmime_pool;
	char *buffer = nullptr;
};
