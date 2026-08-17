#pragma once
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <json/value.h>
#include <gromox/util.hpp>

struct MJSON_MIME;
using MJSON_MIME_ENUM = void (*)(MJSON_MIME *, void *);

struct GX_EXPORT mjson_io {
	std::unordered_map<std::string, std::string> m_cache;
	/*
	 * Subset of m_cache keys that are cheaply reconstructible and safe to
	 * drop between FETCH items (e.g. top-level .eml bodies, which the
	 * wrdat writer re-reads from storage on demand).
	 */
	std::unordered_set<std::string> m_reconstructible;
	using c_iter = decltype(m_cache)::const_iterator;

	bool exists(const std::string &path) const;
	const std::string *get_full(const std::string &path) const;
	std::optional<std::string> get_substr(const std::string &path, size_t of, size_t ln) const;
	ssize_t get_size(const std::string &path) const;
	void place(const std::string &path, std::string &&ctnt, bool evictable = false);
	void drop_reconstructible();
	void clear() { m_reconstructible.clear(); m_cache.clear(); }
	bool valid(c_iter it) const { return it != m_cache.cend(); }
	bool invalid(c_iter it) const { return it == m_cache.cend(); }
};

/**
 * Cache key of a message extracted from a message/rfc822 part.
 *
 * All extractions of one top-level mail share a namespace, "<storage>/<file>".
 * Within it, a message is named by the ids of the rfc822 parts leading to it,
 * joined with dots ("2", "2.3"). The message inside an rfc822-root mail is
 * named "" after the root MIME's empty id, and deeper names keep the empty
 * first hop (".2"). A key built from just the namespace stands for the
 * top-level mail. sub() on that starts the chain, on any other key it extends
 * the chain.
 */
class GX_EXPORT mjson_key {
	public:
	mjson_key() = default;
	explicit mjson_key(std::string_view xns) : m_ns(xns) {}
	mjson_key(std::string_view xns, std::string_view chain) :
		m_ns(xns), m_chain(chain), m_sub(true) {}

	/* key of the message extracted from rfc822 part @id of this message */
	mjson_key sub(const char *id) const
	{
		return m_sub ? mjson_key(m_ns, m_chain + "." + id) :
		       mjson_key(m_ns, id);
	}

	/* cache slot of the extracted message's text */
	std::string msg() const { return m_ns + "/" + m_chain; }
	/* cache slot of the extracted message's digest */
	std::string digest() const { return msg() + ".dgt"; }
	/* name relative to the namespace; the digest's "file" field */
	const std::string &chain() const { return m_chain; }
	const std::string &ns() const { return m_ns; }

	private:
	std::string m_ns, m_chain;
	bool m_sub = false;
};

struct GX_EXPORT MJSON_MIME {
	std::vector<MJSON_MIME> children;
	enum mime_type mime_type = mime_type::none;
	std::string id, ctype, encoding, charset, filename, cid, cntl, cntdspn;
	size_t head = 0, begin = 0, length = 0, lines = 0;

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
		func(this, args...);
		for (auto &c : children)
			c.exec(func, args...);
	}
	template<typename F, typename... Args> void exec(F &&func, Args &&...args) const {
		func(this, args...);
		for (auto &c : children)
			c.exec(func, args...);
	}
};

struct GX_EXPORT MJSON {
	void clear();
	bool load_from_json(const Json::Value &);
	int fetch_structure(mjson_io &, const char *cset, bool ext, std::string &out) const;
	int fetch_envelope(const char *cset, std::string &out) const;
	bool has_rfc822_part() const;
	bool rfc822_build(mjson_io &, const char *storage_path) const;
	bool rfc822_get(mjson_io &, MJSON *other_pjson, const char *storage_path, const char *id, char *mjson_id, char *mime_id) const;
	int rfc822_fetch(mjson_io &, const char *storage_path, const char *cset, bool ext, std::string &out) const;
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
	std::string path, filename, charset, msgid, from, sender, reply, to, cc, bcc;
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
