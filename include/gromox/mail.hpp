#pragma once
#include <memory>
#include <json/value.h>
#include <gromox/defs.h>
#include <gromox/mime.hpp>
#include <gromox/simple_tree.hpp>
#include <gromox/stream.hpp>
#define	MIME_INSERT_BEFORE	SIMPLE_TREE_INSERT_BEFORE
#define MIME_INSERT_AFTER	SIMPLE_TREE_INSERT_AFTER
#define MIME_ADD_FIRST		SIMPLE_TREE_ADD_FIRST
#define	MIME_ADD_LAST		SIMPLE_TREE_ADD_LAST

using MAIL_MIME_ENUM = void (*)(const MIME *, void*);

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
	bool load_from_str_move(char *in_buff, size_t length);
	bool serialize(STREAM *) const;
	bool emit(MIME::write_func, void *) const;
	bool to_file(int fd) const;
	bool to_tls(SSL *) const;
	ssize_t get_length() const;
	MIME *add_head();
	MIME *get_head();
	const MIME *get_head() const;
	bool get_charset(char *out) const;
	int get_digest(size_t *offset, Json::Value &) const;
	MIME *add_child(MIME *base, int opt);
	void enum_mime(MAIL_MIME_ENUM, void *) const;
	bool dup(MAIL *dst);
	bool set_header(const char *hdr, const char *val);

	SIMPLE_TREE tree{};
	std::shared_ptr<MIME_POOL> pmime_pool;
	char *buffer = nullptr;
};
