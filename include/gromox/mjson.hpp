#pragma once
#include <memory>
#include <string>
#include <json/value.h>
#include <gromox/simple_tree.hpp>
#include <gromox/util.hpp>

struct MJSON_MIME;
using MJSON_MIME_ENUM = void (*)(MJSON_MIME *, void *);

struct GX_EXPORT MJSON_MIME {
	SIMPLE_TREE_NODE stree{};
	enum mime_type mime_type = mime_type::none;
	std::string id, ctype, encoding, charset, filename, cid, cntl, cntdspn;
	size_t head = 0, begin = 0, length = 0;

	inline enum mime_type get_mtype() const { return mime_type; }
	inline const char *get_ctype() const { return ctype.c_str(); }
	inline const char *get_charset() const { return charset.c_str(); }
	inline const char *get_filename() const { return filename.c_str(); }
	inline const char *get_encoding() const { return encoding.c_str(); }
	inline const char *get_id() const { return id.c_str(); }
	inline bool ctype_is_rfc822() const { return strcasecmp(get_ctype(), "message/rfc822") == 0; }
	inline bool encoding_is_b() const { return strcasecmp(get_encoding(), "base64") == 0; }
	inline bool encoding_is_q() const { return strcasecmp(get_encoding(), "quoted-printable") == 0; }
	inline size_t get_head_length() const { return begin - head; }
	inline size_t get_content_length() const { return length; }
	inline size_t get_entire_length() const { return get_head_length() + get_content_length(); }
	inline size_t get_head_offset() const { return head; }
	inline size_t get_content_offset() const { return begin; }
};

struct GX_EXPORT MJSON {
	MJSON() = default;
	~MJSON();
	NOMOVE(MJSON);

	void clear();
	BOOL load_from_json(const Json::Value &);
	int fetch_structure(const char *cset, BOOL ext, std::string &out) const;
	int fetch_envelope(const char *cset, std::string &out) const;
	bool has_rfc822_part() const;
	BOOL rfc822_build(const char *storage_path) const;
	BOOL rfc822_get(MJSON *other_pjson, const char *storage_path, const char *id, char *mjson_id, char *mime_id) const;
	int rfc822_fetch(const char *storage_path, const char *cset, BOOL ext, std::string &out) const;
	int seek_fd(const char *id, int whence);
	void enum_mime(MJSON_MIME_ENUM, void *);
	const char *get_mail_filename() const { return filename.c_str(); }
	const char *get_mail_received() const { return received.c_str(); }
	const char *get_mail_messageid() const { return msgid.c_str(); }
	size_t get_mail_length() const { return size; }
	const MJSON_MIME *get_mime(const char *id) const;

	SIMPLE_TREE stree{};
	bool read = false, replied = false, forwarded = false, unsent = false;
	bool flag = false;
	unsigned int priority = 0, uid = 0;
	int message_fd = -1;
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
