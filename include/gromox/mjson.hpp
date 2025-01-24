#pragma once
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include <json/value.h>
#include <gromox/util.hpp>

struct MJSON_MIME;
using MJSON_MIME_ENUM = void (*)(MJSON_MIME *, void *);

struct GX_EXPORT mjson_io {
	std::unordered_map<std::string, std::string> m_cache;
	using c_iter = decltype(m_cache)::const_iterator;

	bool exists(const std::string &path) const;
	c_iter find(const std::string &path);
	void place(const std::string &path, std::string &&ctnt);
	void clear() { m_cache.clear(); }
	bool valid(c_iter it) const { return it != m_cache.cend(); }
	bool invalid(c_iter it) const { return it == m_cache.cend(); }
	static std::string substr(c_iter it, size_t of, size_t ln);
};

struct GX_EXPORT MJSON_MIME {
	std::vector<MJSON_MIME> children;
	enum mime_type mime_type = mime_type::none;
	std::string id, ctype, encoding, charset, filename, cid, cntl, cntdspn;
	size_t head = 0, begin = 0, length = 0;

	bool contains_none_type() const;
	const MJSON_MIME *find_by_id(const char *) const;
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
	template<typename F, typename... Args> void exec(F &&func, Args &&...args) {
		func(this, std::forward<Args>(args)...);
		for (auto &c : children)
			c.exec(func, std::forward<Args>(args)...);
	}
	template<typename F, typename... Args> void exec(F &&func, Args &&...args) const {
		func(this, std::forward<Args>(args)...);
		for (auto &c : children)
			c.exec(func, std::forward<Args>(args)...);
	}
};

struct GX_EXPORT MJSON {
	void clear();
	BOOL load_from_json(const Json::Value &);
	int fetch_structure(mjson_io &, const char *cset, BOOL ext, std::string &out) const;
	int fetch_envelope(const char *cset, std::string &out) const;
	bool has_rfc822_part() const;
	BOOL rfc822_build(mjson_io &, const char *storage_path) const;
	BOOL rfc822_get(mjson_io &, MJSON *other_pjson, const char *storage_path, const char *id, char *mjson_id, char *mime_id) const;
	int rfc822_fetch(mjson_io &, const char *storage_path, const char *cset, BOOL ext, std::string &out) const;
	const char *get_mail_filename() const { return filename.c_str(); }
	const char *get_mail_received() const { return received.c_str(); }
	const char *get_mail_messageid() const { return msgid.c_str(); }
	size_t get_mail_length() const { return size; }
	const MJSON_MIME *get_mime(const char *id) const;

	std::optional<MJSON_MIME> m_root;
	bool read = false, replied = false, forwarded = false, unsent = false;
	bool flag = false;
	unsigned int priority = 0, uid = 0;
	size_t size = 0;
	std::string path, filename, charset, msgid, from, sender, reply, to, cc;
	std::string inreply, subject, received, date, ref, notification;

	template<typename... Args> void enum_mime(Args &&...args) {
		if (m_root.has_value())
			m_root->exec(std::forward<Args>(args)...);
	}
	template<typename... Args> void enum_mime(Args &&...args) const {
		if (m_root.has_value())
			m_root->exec(std::forward<Args>(args)...);
	}
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
