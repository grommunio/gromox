#pragma once
#include <memory>
#include <string>
#include <gromox/mime_pool.hpp>
#include <gromox/simple_tree.hpp>
#include <gromox/util.hpp>

struct MJSON_MIME;
using MJSON_MIME_ENUM = void (*)(MJSON_MIME *, void *);

struct MJSON_MIME {
	SIMPLE_TREE_NODE node{};
	alloc_limiter<MJSON_MIME> *ppool = nullptr;
	enum mime_type mime_type = mime_type::none;
	char id[64]{}, ctype[256]{}, encoding[32]{}, charset[32]{};
	char filename[256]{}, cid[128]{}, cntl[256]{}, cntdspn[64]{};
	size_t head = 0, begin = 0, length = 0;

	inline enum mime_type get_mtype() const { return mime_type; }
	inline const char *get_ctype() const { return ctype; }
	inline bool ctype_is_rfc822() const { return strcasecmp(get_ctype(), "message/rfc822") == 0; }
	inline const char *get_charset() const { return charset; }
	inline const char *get_filename() const { return filename; }
	inline const char *get_encoding() const { return encoding; }
	inline bool encoding_is_b() const { return strcasecmp(get_encoding(), "base64") == 0; }
	inline bool encoding_is_q() const { return strcasecmp(get_encoding(), "quoted-printable") == 0; }
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
	const char *get_mail_filename() const { return filename.c_str(); }
	const char *get_mail_received() const { return received.c_str(); }
	const char *get_mail_messageid() const { return msgid.c_str(); }
	size_t get_mail_length() const { return size; }
	MJSON_MIME *get_mime(const char *id);

	SIMPLE_TREE tree{};
	alloc_limiter<MJSON_MIME> *ppool = nullptr;
	unsigned int uid = 0;
	int message_fd = -1;
	int read = 0, replied = 0, forwarded = 0, unsent = 0;
	int flag = 0, priority = 0;
	size_t size = 0;
	std::string path, filename, charset, msgid, from, sender, reply, to, cc;
	std::string inreply, subject, received, date, ref, notification;
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

extern GX_EXPORT alloc_limiter<MJSON_MIME> mjson_allocator_init(size_t max_size, const char *name = nullptr, const char *hint = nullptr);
