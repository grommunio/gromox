// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2025 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <fmt/core.h>
#include <libHX/ctype_helper.h>
#include <libHX/defs.h>
#include <libHX/io.h>
#include <libHX/string.h>
#include <vmime/mailboxList.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/json.hpp>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mjson.hpp>
#include <gromox/util.hpp>
#define MAX_RFC822_DEPTH	5

#define MAX_DIGLEN			256*1024

using namespace std::string_literals;
using namespace gromox;

enum {
	TYPE_STRUCTURE,
	TYPE_MIMES
};

namespace {

struct ENUM_PARAM {
	const char *id;
	const MJSON_MIME *pmime;
};

struct BUILD_PARAM {
	mjson_io &io;
	const char *filename = nullptr, *msg_path = nullptr;
	const char *storage_path = nullptr;
	int depth = 0;
	BOOL build_result = false;
};

}

static bool mjson_parse_array(MJSON *, const Json::Value &, unsigned int type);
static BOOL mjson_record_node(MJSON *, const Json::Value &, unsigned int type);
static int mjson_fetch_mime_structure(mjson_io &, const MJSON_MIME *, const char *storage_path, const char *msg_filename, const char *cset, const char *email_charset, BOOL b_ext, std::string &out);
static std::string mjson_cvt_addr(const EMAIL_ADDR &);
static std::string mjson_add_backslash(const char *);
static void mjson_enum_build(const MJSON_MIME *, BUILD_PARAM *);
static int mjson_rfc822_fetch_internal(mjson_io &, const MJSON *, const char *storage_path, const char *cset, BOOL b_ext, std::string &out);

bool mjson_io::exists(const std::string &path) const
{
	return m_cache.find(path) != m_cache.cend();
}

mjson_io::c_iter mjson_io::find(const std::string &path)
{
	auto iter = m_cache.find(path);
	if (iter != m_cache.cend())
		return iter;
	/*
	 * Not finding the element is not an error; asking for `BODY[2.1.3]`
	 * will iteratively look for /2.1.3.dgt, /2.1.dgt, /2.dgt.
	 */
	return m_cache.cend();
}

void mjson_io::place(const std::string &path, std::string &&content)
{
	m_cache[path] = std::move(content);
}

std::string mjson_io::substr(mjson_io::c_iter it, size_t of, size_t len)
{
	const auto &str = it->second;
	if (of <= str.size())
		return str.substr(of, len);
	return {};
}

bool MJSON_MIME::contains_none_type() const
{
	if (mime_type == mime_type::none)
		return true;
	for (const auto &c : children)
		if (c.contains_none_type())
			return true;
	return false;
}

const MJSON_MIME *MJSON_MIME::find_by_id(const char *key) const
{
	if (strcmp(get_id(), key) == 0)
		return this;
	for (auto &c : children) {
		auto r = c.find_by_id(key);
		if (r != nullptr)
			return r;
	}
	return nullptr;
}

/*
 *	clear the mjson mime nodes from the tree and
 *  the head information of mail
 *	@param
 *		pjson [in]			indicate the mail object
 */
void MJSON::clear()
{
	auto pjson = this;
	m_root.reset();
	pjson->uid = 0;
	pjson->path.clear();
	pjson->filename.clear();
	pjson->msgid.clear();
	pjson->from.clear();
	pjson->sender.clear();
	pjson->reply.clear();
	pjson->to.clear();
	pjson->cc.clear();
	pjson->inreply.clear();
	pjson->subject.clear();
	pjson->received.clear();
	pjson->date.clear();
	pjson->ref.clear();
	pjson->read = 0;
	pjson->replied = 0;
	pjson->forwarded = 0;
	pjson->unsent = 0;
	pjson->flag = 0;
	pjson->priority = 0;
	pjson->notification.clear();
	pjson->size = 0;
}

BOOL MJSON::load_from_json(const Json::Value &root) try
{
	auto pjson = this;
	clear();
	{
		pjson->filename     = root["file"].asString();
		pjson->uid          = root["uid"].asUInt();
		pjson->msgid        = base64_decode(root["msgid"].asString());
		pjson->from         = base64_decode(root["from"].asString());
		pjson->charset      = root["charset"].asString();
		pjson->sender       = base64_decode(root["sender"].asString());
		pjson->reply        = base64_decode(root["reply"].asString());
		pjson->to           = base64_decode(root["to"].asString());
		pjson->cc           = base64_decode(root["cc"].asString());
		pjson->inreply      = base64_decode(root["inreply"].asString());
		pjson->subject      = base64_decode(root["subject"].asString());
		pjson->received     = base64_decode(root["received"].asString());
		HX_strltrim(pjson->received.data());
		pjson->received.resize(strlen(pjson->received.data()));
		pjson->date         = base64_decode(root["date"].asString());
		pjson->notification = base64_decode(root["notification"].asString());
		pjson->read         = root["read"].asBool();
		pjson->replied      = root["replied"].asBool();
		pjson->unsent       = root["unsent"].asBool();
		pjson->forwarded    = root["forwarded"].asBool();
		pjson->flag         = root["flag"].asBool();
		pjson->priority     = root["priority"].asUInt();
		pjson->ref          = base64_decode(root["ref"].asString());
		if (!mjson_parse_array(pjson, root["structure"], TYPE_STRUCTURE) ||
		    !mjson_parse_array(pjson, root["mimes"], TYPE_MIMES))
			return false;
		pjson->size         = root["size"].asUInt();
	}
	return m_root.has_value() && !m_root->contains_none_type();
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2743: ENOMEM");
	return false;
}

const MJSON_MIME *MJSON::get_mime(const char *id) const
{
	return m_root.has_value() ? m_root->find_by_id(id) : nullptr;
}

static BOOL mjson_record_node(MJSON *pjson, const Json::Value &jv, unsigned int type) try
{
	MJSON_MIME temp_mime;
	temp_mime.mime_type = type == TYPE_STRUCTURE ? mime_type::multiple : mime_type::single;

	auto &m    = temp_mime;
	m.id       = jv["id"].asString();
	m.ctype    = jv["ctype"].asString();
	m.encoding = jv["encoding"].asString();
	m.charset  = jv["charset"].asString();
	m.filename = base64_decode(jv["filename"].asString());
	m.cid      = base64_decode(jv["cid"].asString());
	m.cntl     = base64_decode(jv["cntl"].asString());
	m.cntdspn  = jv["cntdspn"].asString();
	m.head     = jv["head"].asUInt();
	m.begin    = jv["begin"].asUInt();
	m.length   = jv["length"].asUInt();
	if (m.ctype.empty())
		m.ctype = "application/octet-stream";

	/* for some MUA such as Foxmail, use application/octet-stream
	   as the Content-Type, so make the revision for these mimes
	*/
	if (class_match_suffix(temp_mime.filename.c_str(), ".eml") == 0 &&
	    !temp_mime.ctype_is_rfc822())
		temp_mime.ctype = "message/rfc822";

	if (temp_mime.id.empty()) {
		if (pjson->m_root.has_value())
			return false; /* collision */
		pjson->m_root.emplace(std::move(m));
		return TRUE;
	}
	auto pmime = &*pjson->m_root;
	auto part_ptr = temp_mime.id.c_str();
	while (true) {
		char *end;
		unsigned int offset = strtoul(part_ptr, &end, 10);
		if (end == part_ptr)
			return false;
		if (*end != '\0' && *end != '.')
			return false;
		if (offset < 1)
			return false;
		if (pmime->children.size() < offset)
			pmime->children.resize(offset);
		--offset;
		if (*end == '\0') {
			pmime->children[offset] = std::move(m);
			return true;
		}
		pmime = &pmime->children[offset];
		part_ptr = end + 1;
	}
	return false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2062: ENOMEM");
	return false;
}

static bool mjson_parse_array(MJSON *m, const Json::Value &jv, unsigned int type)
{
	if (!jv.isArray())
		return false;
	for (const auto &e : jv) {
		if (e.type() == Json::arrayValue && e.size() == 1 &&
		    e[0].type() == Json::objectValue) {
			if (!mjson_record_node(m, e[0], type))
				return false;
			continue;
		}
		if (e.type() != Json::objectValue)
			return false;
		if (!mjson_record_node(m, e, type))
			return false;
	}
	return true;
}

int MJSON::fetch_structure(mjson_io &io, const char *cset, BOOL b_ext,
    std::string &buf) const try
{
	if (!m_root.has_value())
		return -1;
	return mjson_fetch_mime_structure(io, &*m_root, nullptr, nullptr, cset,
	       charset.c_str(), b_ext, buf);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2061: ENOMEM");
	return -1;
}

static int mjson_fetch_mime_structure(mjson_io &io, const MJSON_MIME *pmime,
    const char *storage_path, const char *msg_filename, const char *charset,
    const char *email_charset, BOOL b_ext, std::string &buf) try
{
#ifdef _DEBUG_UMTA
	if (pmime == nullptr) {
		mlog(LV_DEBUG, "mail: NULL pointer in mjson_fetch_mime_structure");
		return -1;
	}
#endif
	auto ctype = pmime->ctype;
	HX_strupper(ctype.data());
	auto pos = ctype.find('/');
	std::string psubtype;
	if (pos != ctype.npos) {
		psubtype = ctype.substr(pos + 1);
		ctype.erase(pos);
	}
	
	if (pmime->get_mtype() == mime_type::single ||
	    pmime->get_mtype() == mime_type::single_obj) {
		/*
		 * Note: Do not add a space before opening parenthesis under
		 * any circumstances (even if offset>0).
		 */
		if (psubtype.empty())
			buf += fmt::format("(\"{}\" NIL", ctype);
		else
			buf += fmt::format("(\"{}\" \"{}\"", ctype, psubtype);
		if (*pmime->get_charset() != '\0' || *pmime->get_filename() != '\0') {
			buf += " (";
			bool b_space = false;
			if (*pmime->get_charset() != '\0') {
				buf += "\"CHARSET\" \""s + pmime->get_charset() + "\"";
				b_space = TRUE;
			} else if (strcasecmp(ctype.c_str(), "text") == 0 &&
			    *email_charset != '\0') {
				buf += "\"CHARSET\" \""s + email_charset + "\"";
				b_space = TRUE;
			}
			
			if (*pmime->get_filename() != '\0') {
				if (b_space)
					buf += ' ';
				if (str_isasciipr(pmime->get_filename()))
					buf += "\"NAME\" \"" +
					       mjson_add_backslash(pmime->get_filename()) +
					       "\"";
				else
					buf += fmt::format("\"NAME\" \"=?{}?b?{}?=\"",
					       *email_charset != '\0' ? email_charset : charset,
					       base64_encode(pmime->get_filename()));
			}
			buf += ')';
		} else {
			buf += " NIL";
		}
		buf += pmime->cid.size() > 0 && str_isasciipr(pmime->cid.c_str()) ?
		       mjson_add_backslash(pmime->cid.c_str()) + "\"" :
		       " NIL";
		
		/* body description */
		buf += " NIL";
		if (*pmime->get_encoding() == '\0') {
			buf += " NIL";
		} else if (storage_path != nullptr && msg_filename != nullptr &&
		    pmime->ctype_is_rfc822()) {
			/* revision for APPLE device */
			if (pmime->encoding_is_b() ||
			    pmime->encoding_is_q())
				buf += " \"7bit\"";
			else
				buf += " \""s + pmime->get_encoding() + "\"";
		} else {
			buf += " \""s + pmime->get_encoding() + "\"";
		}
		
		if (NULL != storage_path && NULL != msg_filename &&
		    pmime->ctype_is_rfc822() &&
		    (pmime->encoding_is_b() || pmime->encoding_is_q())) {
			std::string temp_path;
			if (*msg_filename == '\0')
				temp_path = storage_path + "/"s + pmime->get_id();
			else
				temp_path = storage_path + "/"s + msg_filename + "." + pmime->get_id();
			auto fd = io.find(temp_path);
			buf += io.valid(fd) ?
			       " " + std::to_string(fd->second.size()) :
			       " NIL";
		} else {
			buf += " " + std::to_string(pmime->length);
		}
					
		if (strcasecmp(ctype.c_str(), "TEXT") == 0)
			/* body lines */
			buf += " 0";
		
		if (NULL != storage_path && NULL != msg_filename &&
		    pmime->ctype_is_rfc822()) {
			std::string temp_path;
			
			if (*msg_filename == '\0')
				temp_path = storage_path + "/"s + pmime->get_id() + ".dgt";
			else
				temp_path = storage_path + "/"s + msg_filename +
				            "." + pmime->get_id() + ".dgt";

			auto fd = io.find(temp_path);
			if (io.invalid(fd))
				goto RFC822_FAILURE;
			Json::Value digest;
			if (!json_from_str(fd->second, digest))
				goto RFC822_FAILURE;
			MJSON temp_mjson;
			if (!temp_mjson.load_from_json(digest))
				goto RFC822_FAILURE;
			temp_mjson.path = storage_path;
			buf += ' ';
			std::string envl;
			auto envl_len = temp_mjson.fetch_envelope(charset, envl);
			if (envl_len == -1)
				goto RFC822_FAILURE;
			buf += std::move(envl);
			buf += ' ';
			std::string body;
			auto body_len = mjson_rfc822_fetch_internal(io, &temp_mjson,
			                storage_path, charset, b_ext, body);
			if (body_len == -1)
				goto RFC822_FAILURE;
			buf += std::move(body);
			goto RFC822_SUCCESS;
		}
		
 RFC822_FAILURE:
		if (b_ext) {
			buf += " NIL"; /* body MD5 */
			buf += pmime->cntdspn.size() > 0 ?
			       " (\""s + pmime->cntdspn + "\" NIL)" :
			       " NIL"s;
			buf += " NIL"; /* body language */
			buf += pmime->cntl.size() > 0 && str_isasciipr(pmime->cntl.c_str()) ?
			       " " + mjson_add_backslash(pmime->cntl.c_str()) :
			       " NIL";
		}
		
 RFC822_SUCCESS:
		buf += ')';
	} else if (pmime->get_mtype() == mime_type::multiple) {
		buf += '(';
		for (auto &c : pmime->children)
			if (mjson_fetch_mime_structure(io, &c,
			    storage_path, msg_filename, charset, email_charset,
			    b_ext, buf) != 0)
				return -1;
		if (psubtype.empty())
			buf += " NIL";
		else
			buf += " \""s + psubtype + "\"";
		if (b_ext)
			buf += " NIL NIL NIL";
		buf += ')';
	} else {
		return -1;
	}
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1322: ENOMEM");
	return -1;
}

static std::string mjson_cvt_addr(const EMAIL_ADDR &email_addr)
{
	std::string buf;
	if (*email_addr.display_name == '\0')
		buf += "(NIL";
	else if (str_isasciipr(email_addr.display_name))
		buf += "(\"" + mjson_add_backslash(email_addr.display_name) + "\"";
	else
		/*
		 * qp_encode_ex is only suitable for bodytext but not
		 * encoded-words, so just pick base64
		 */
		buf += "(\"=?utf-8?b?" + base64_encode(email_addr.display_name) + "?=\"";

	buf += " NIL"; /* at-domain-list */
	buf += *email_addr.local_part != '\0' ?
	       " \"" + mjson_add_backslash(email_addr.local_part) + "\"" :
	       " NIL";
	buf += *email_addr.domain != '\0' ?
	       " \"" + mjson_add_backslash(email_addr.domain) + "\")" :
	       " NIL)";
	return buf;
}

static void mjson_emit_adrlist(const std::string &al, std::string &buf)
{
	vmime::mailboxList vmlist;
	vmlist.parse(al);
	if (vmlist.isEmpty()) {
		buf += " NIL";
		return;
	}
	buf += " (";
	bool second = false;
	for (auto entry : vmlist.getMailboxList()) {
		if (second)
			buf += ' ';
		second = true;
		buf += mjson_cvt_addr(*entry);
	}
	buf += ')';
}

int MJSON::fetch_envelope(const char *cset, std::string &buf) const try
{
	/* RFC 9051 §7.5.2 ENVELOPE */
	buf += date.size() > 0 && str_isasciipr(date.c_str()) ?
	       "(\"" + mjson_add_backslash(date.c_str()) + "\"" :
	       "(NIL";
	if (subject.size() == 0)
		buf += " NIL";
	else if (str_isasciipr(subject.c_str()))
		buf += " \"" + mjson_add_backslash(subject.c_str()) + "\"";
	else
		buf += fmt::format(" \"=?{}?b?{}?=\"",
		       charset.size() > 0 ? charset.c_str() : cset,
		       base64_encode(subject));

	buf += fmt::format(" ({}) ({}) ({})",
	       mjson_cvt_addr(from.c_str()),
	       mjson_cvt_addr(sender.size() > 0 ? sender.c_str() : from.c_str()),
	       mjson_cvt_addr(reply.size() > 0 ? reply.c_str() : from.c_str()));
	mjson_emit_adrlist(to, buf);
	mjson_emit_adrlist(cc, buf);
	buf += " NIL"; /* bcc */
	buf += inreply.size() > 0 && str_isasciipr(inreply.c_str()) ?
	       " \"" + mjson_add_backslash(inreply.c_str()) + "\"" :
	       " NIL";
	buf += *get_mail_messageid() != '\0' &&
	       str_isasciipr(get_mail_messageid()) ?
	       " \"" + mjson_add_backslash(get_mail_messageid()) + "\")" :
	       " NIL)";
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1755: ENOMEM");
	return -1;
}

static std::string mjson_add_backslash(const char *s)
{
	std::unique_ptr<char[], stdlib_delete> q(HX_strquote(s, HXQUOTE_DQUOTE, nullptr));
	return q.get();
}

bool MJSON::has_rfc822_part() const
{
	bool b_found = false;
	enum_mime([](const MJSON_MIME *m, bool &found) {
		if (!found && m->ctype_is_rfc822())
			found = true;
		}, b_found);
	return b_found;
}

static void mjson_enum_build(const MJSON_MIME *pmime, BUILD_PARAM *pbuild) { try
{
	if (!pbuild->build_result || pbuild->depth > MAX_RFC822_DEPTH ||
	    !pmime->ctype_is_rfc822())
		return;
	auto temp_path = pbuild->msg_path + "/"s + pbuild->filename;
	std::string msg_path, dgt_path;
	if (1 == pbuild->depth) {
		msg_path = pbuild->storage_path + "/"s + pmime->get_id();
		dgt_path = msg_path + ".dgt";
	} else {
		msg_path = pbuild->storage_path + "/"s + pbuild->filename +
		           "/" + pmime->get_id();
		dgt_path = msg_path + ".dgt";
	}
		
	auto iter = pbuild->io.find(temp_path);
	if (pbuild->io.invalid(iter)) {
		pbuild->build_result = FALSE;
		return;
	}
	
	auto eml = mjson_io::substr(iter, pmime->get_content_offset(), pmime->get_content_length());
	if (pmime->encoding_is_b()) {
		eml = base64_decode(eml);
	} else if (pmime->encoding_is_q()) {
		std::string qpout;
		qpout.resize(eml.size());
		auto qdlen = qp_decode_ex(qpout.data(), qpout.size(), eml.c_str(), eml.size());
		if (qdlen < 0) {
			pbuild->build_result = false;
			return;
		}
		eml = std::move(qpout);
	}
	
	MJSON temp_mjson;
	MAIL imail;
	if (!imail.load_from_str(eml.c_str(), eml.size())) {
		pbuild->build_result = FALSE;
		return;
	}
	size_t mess_len;
	std::string regurg;
	auto err = imail.to_str(regurg);
	if (err != 0) {
		mlog(LV_ERR, "E-1768: %s", strerror(err));
		pbuild->build_result = FALSE;
		return;
	}
	pbuild->io.place(msg_path, std::move(regurg));
	Json::Value digest;
	auto result = imail.make_digest(&mess_len, digest);
	imail.clear();
	if (result <= 0) {
		pbuild->build_result = FALSE;
		return;
	}
	if (pbuild->depth == 1)
		digest["file"] = pmime->get_id();
	else
		digest["file"] = std::string(pbuild->filename) + "." + pmime->get_id();
	pbuild->io.place(dgt_path, json_to_str(digest));
	if (!temp_mjson.load_from_json(digest)) {
		pbuild->build_result = FALSE;
		return;
	}
	temp_mjson.path = pbuild->storage_path;
	
	if (pbuild->depth >= MAX_RFC822_DEPTH || !temp_mjson.has_rfc822_part())
		return;
	BUILD_PARAM build_param{pbuild->io};
	build_param.filename = temp_mjson.get_mail_filename();
	build_param.msg_path = temp_mjson.path.c_str();
	build_param.storage_path = pbuild->storage_path;
	build_param.depth = pbuild->depth + 1;
	build_param.build_result = TRUE;

	temp_mjson.enum_mime(mjson_enum_build, &build_param);
	if (!build_param.build_result)
		pbuild->build_result = FALSE;
} catch (const std::bad_alloc &) {
	pbuild->build_result = false;
	mlog(LV_ERR, "E-1138: ENOMEM");
}}

BOOL MJSON::rfc822_build(mjson_io &io, const char *storage_path) const
{
	auto pjson = this;
	if (!has_rfc822_part())
		return FALSE;
	if (pjson->path.empty())
		return FALSE;
	auto temp_path = storage_path + "/"s + pjson->get_mail_filename();
	BUILD_PARAM build_param{io};
	build_param.filename = pjson->get_mail_filename();
	build_param.msg_path = pjson->path.c_str();
	build_param.storage_path = temp_path.c_str();
	build_param.depth = 1;
	build_param.build_result = TRUE;
	pjson->enum_mime(mjson_enum_build, &build_param);
	return build_param.build_result;
}

BOOL MJSON::rfc822_get(mjson_io &io, MJSON *pjson, const char *storage_path,
    const char *id, char *mjson_id, char *mime_id) const try
{
	auto pjson_base = this;
	char *pdot;
	char temp_path[256];

	if (!has_rfc822_part())
		return FALSE;
	snprintf(temp_path, std::size(temp_path), "%s/%s", storage_path,
	         pjson_base->get_mail_filename());
	
	snprintf(mjson_id, 64, "%s.", id);
	while (NULL != (pdot = strrchr(mjson_id, '.'))) {
		*pdot = '\0';
		char dgt_path[256];
		snprintf(dgt_path, std::size(dgt_path), "%s/%s/%s.dgt", storage_path,
		         pjson_base->get_mail_filename(), mjson_id);
		auto fd = io.find(dgt_path);
		if (io.invalid(fd))
			continue;
		pjson->clear();
		Json::Value digest;
		if (!json_from_str(fd->second, digest) ||
		    !pjson->load_from_json(digest))
			return false;
		pjson->path = temp_path;
		strcpy(mime_id, pdot + 1);
		return TRUE;
	}
	return FALSE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1321: ENOMEM");
	return false;
}
	
int MJSON::rfc822_fetch(mjson_io &io, const char *storage_path,
    const char *cset, BOOL b_ext, std::string &buf) const
{
	auto pjson = this;
#ifdef _DEBUG_UMTA
	if (storage_path == nullptr) {
		mlog(LV_DEBUG, "mail: NULL pointer in mjson_rfc822_fetch");
		return -1;
	}
#endif
	if (!has_rfc822_part())
		return -1;
	auto temp_path = storage_path + "/"s + get_mail_filename();
	if (!m_root.has_value())
		return -1;
	return mjson_fetch_mime_structure(io, &*m_root, temp_path.c_str(), "",
	       cset, pjson->charset.c_str(), b_ext, buf);
}

static int mjson_rfc822_fetch_internal(mjson_io &io, const MJSON *pjson,
    const char *storage_path, const char *charset, BOOL b_ext, std::string &buf)
{
#ifdef _DEBUG_UMTA
	if (pjson == nullptr || storage_path == nullptr) {
		mlog(LV_DEBUG, "mail: NULL pointer in mjson_rfc822_fetch_internal");
		return -1;
	}
#endif
	if (!pjson->m_root.has_value())
		return -1;
	return mjson_fetch_mime_structure(io, &*pjson->m_root, storage_path,
	       pjson->get_mail_filename(), charset,
	       pjson->charset.c_str(), b_ext, buf);
}
