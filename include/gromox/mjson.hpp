#pragma once
#include <memory>
#include <gromox/mime_pool.hpp>
#include <gromox/simple_tree.hpp>
#include <gromox/util.hpp>

#define MJSON_MIME_NONE			0

#define MJSON_MIME_SINGLE		1

#define MJSON_MIME_MULTIPLE		2

struct MJSON_MIME;
using MJSON_MIME_ENUM = void (*)(MJSON_MIME *, void *);

struct MJSON_MIME {
	SIMPLE_TREE_NODE node;
	alloc_limiter<MJSON_MIME> *ppool;
	int			mime_type;
	char        id[64];
	char 		ctype[256];
	char        encoding[32];
	char        charset[32];
	char        filename[256];
	char        cid[128];
	char        cntl[256];
	char        cntdspn[64];
	size_t      head;
	size_t      begin;
	size_t		length;

	inline int get_mtype() const { return mime_type; }
	inline const char *get_ctype() const { return ctype; }
	inline const char *get_charset() const { return charset; }
	inline const char *get_filename() const { return filename; }
	inline const char *get_encoding() const { return encoding; }
	inline const char *get_id() const { return id; }
	size_t get_length(unsigned int param) const;
	size_t get_offset(unsigned int param) const;
};

struct GX_EXPORT MJSON {
	MJSON() = default;
	MJSON(alloc_limiter<MJSON_MIME> *);
	~MJSON();
	NOMOVE(MJSON);

	void clear();
	BOOL retrieve(char *digest_buf, int len, const char *path);
	int fetch_structure(const char *charset, BOOL ext, char *buf, int len);
	int fetch_envelope(const char *charset, char *buf, int len);
	BOOL rfc822_check();
	BOOL rfc822_build(std::shared_ptr<MIME_POOL>, const char *storage_path);
	BOOL rfc822_get(MJSON *other_pjson, const char *storage_path, const char *id, char *mjson_id, char *mime_id);
	int rfc822_fetch(const char *storage_path, const char *charset, BOOL ext, char *buf, int len);
	int seek_fd(const char *id, int whence);
	void enum_mime(MJSON_MIME_ENUM, void *);
	const char *get_mail_filename() const { return filename; }
	const char *get_mail_received() const { return received; }
	const char *get_mail_messageid() const { return msgid; }
	size_t get_mail_length() const { return size; }
	MJSON_MIME *get_mime(const char *id);

	SIMPLE_TREE tree{};
	alloc_limiter<MJSON_MIME> *ppool = nullptr;
	unsigned int uid = 0;
	int message_fd = -1;
	int read = 0, replied = 0, forwarded = 0, unsent = 0;
	int flag = 0, priority = 0;
	size_t size = 0;
	char path[256]{}, filename[128]{}, charset[32]{}, msgid[1024]{};
	char from[1024]{}, sender[1024]{}, reply[1024]{};
	char to[16*1024]{}, cc[16*1024]{}, inreply[1024]{}, subject[1024]{};
	char received[256]{}, date[256]{}, ref[4096]{};
	char notification[1024]{};
};

enum {
	MJSON_FLAG_READ,
	MJSON_FLAG_REPLIED,
	MJSON_FLAG_FORWARDED,
	MJSON_FLAG_UNSENT,
	MJSON_FLAG_FLAG
};

enum {
	MJSON_MIME_HEAD,
	MJSON_MIME_CONTENT,
	MJSON_MIME_ENTIRE
};

extern GX_EXPORT alloc_limiter<MJSON_MIME> mjson_allocator_init(size_t max_size);
