// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
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
#include <sys/stat.h>
#include <sys/types.h>
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
	const char *filename = nullptr, *msg_path = nullptr;
	const char *storage_path = nullptr;
	int depth = 0;
	BOOL build_result = false;
};

}

static void mjson_enum_delete(SIMPLE_TREE_NODE *pnode);
static bool mjson_parse_array(MJSON *, const Json::Value &, unsigned int type);
static BOOL mjson_record_node(MJSON *, const Json::Value &, unsigned int type);
static int mjson_fetch_mime_structure(const MJSON_MIME *,
	const char *storage_path, const char *msg_filename, const char* charset,
	const char *email_charset, BOOL b_ext, std::string &out);
static std::string mjson_cvt_addr(const EMAIL_ADDR &);
static std::string mjson_add_backslash(const char *);
static void mjson_emum_rfc822(MJSON_MIME *, void *);
static void mjson_enum_build(MJSON_MIME *, void *);
static int mjson_rfc822_fetch_internal(const MJSON *, const char *storage_path, const char *cset, BOOL b_ext, std::string &out);

/*
 *	clear the mjson mime nodes from the tree and
 *  the head information of mail
 *	@param
 *		pjson [in]			indicate the mail object
 */
void MJSON::clear()
{
	auto pjson = this;
	auto pnode = pjson->stree.get_root();
	if (pnode != nullptr)
		pjson->stree.destroy_node(pnode, mjson_enum_delete);
	if (-1 != pjson->message_fd) {
		close(pjson->message_fd);
		pjson->message_fd = -1;
	}
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

static void mjson_enum_delete(SIMPLE_TREE_NODE *pnode)
{
#ifdef _DEBUG_UMTA
	if (NULL == pnode) {
		mlog(LV_DEBUG, "mail: NULL pointer in mjson_enum_delete");
		return;
	}
#endif
	delete static_cast<MJSON_MIME *>(pnode->pdata);
}

MJSON::~MJSON()
{
	clear();
	stree.clear();
}

BOOL MJSON::load_from_json(const Json::Value &root) try
{
	auto pjson = this;
	BOOL b_none;
	
#ifdef _DEBUG_UMTA
	if (digest_buff == nullptr) {
		mlog(LV_DEBUG, "mail: NULL pointer in mjson_retrieve");
		return FALSE;
	}
#endif
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
	auto pnode = pjson->stree.get_root();
	if (pnode == nullptr)
		return FALSE;
	/* check for NONE mime in tree */
	b_none = FALSE;
	simple_tree_enum_from_node(pnode, [&](const tree_node *nd, unsigned int) {
		if (static_cast<MJSON_MIME *>(nd->pdata)->mime_type == mime_type::none)
			b_none = TRUE;
	});
	if (b_none)
		return FALSE;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2743: ENOMEM");
	return false;
}

void MJSON::enum_mime(MJSON_MIME_ENUM enum_func, void *param)
{
	auto pjson = this;
#ifdef _DEBUG_UMTA
	if (enum_func == nullptr) {
        mlog(LV_DEBUG, "mail: NULL pointer in mjson_enum_mime");
        return;
    }
#endif
	auto r = pjson->stree.get_root();
	if (r == nullptr)
		return;
	simple_tree_enum_from_node(r, [&](tree_node *stn, unsigned int) {
		auto m = containerof(stn, MJSON_MIME, stree);
		enum_func(m, param);
	});
}

/*
 *	get file description of mail file and seek pointer to location
 *	@param
 *		pjson [in]			indicate the mjson object
 *		id [in]				id string of mime
 *		whence				MJSON_MIME_HEAD
 *							MJSON_MIME_CONTENT
 */
int MJSON::seek_fd(const char *id, int whence)
{
	auto pjson = this;
	if (pjson->path.empty())
		return -1;
	if (whence != MJSON_MIME_HEAD && whence != MJSON_MIME_CONTENT)
		return -1;
	auto pmime = pjson->get_mime(id);
	if (pmime == nullptr)
		return -1;
	
	if (-1 == pjson->message_fd) {
		try {
			auto temp_path = std::string(pjson->path) + "/" + pjson->filename;
			pjson->message_fd = open(temp_path.c_str(), O_RDONLY);
		} catch (const std::bad_alloc &) {
			mlog(LV_ERR, "E-1476: ENOMEM");
		}
		if (pjson->message_fd == -1)
			return -1;
	}
	
	switch (whence) {
	case MJSON_MIME_HEAD:
		lseek(pjson->message_fd, pmime->head, SEEK_SET);
		break;
	case MJSON_MIME_CONTENT:
		lseek(pjson->message_fd, pmime->begin, SEEK_SET);
		break;
	}
	return pjson->message_fd;
}

/*
 *	get mime from mjson object
 *	@param
 *		pmime [in]			indicate the mime object
 */
const MJSON_MIME *MJSON::get_mime(const char *id) const
{
	ENUM_PARAM enum_param = {id};
	simple_tree_enum_from_node(stree.get_root(), [&](const tree_node *nd, unsigned int) {
		if (enum_param.pmime != nullptr)
			return;
		auto m = static_cast<const MJSON_MIME *>(nd->pdata);
		if (strcmp(m->get_id(), enum_param.id) == 0)
			enum_param.pmime = m;
	});
	return enum_param.pmime;
}

static BOOL mjson_record_node(MJSON *pjson, const Json::Value &jv, unsigned int type) try
{
	int j, last_pos = 0;
	char temp_buff[64];
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
	auto temp_len = temp_mime.filename.size();
	if (class_match_suffix(temp_mime.filename.c_str(), ".eml") == 0 &&
	    !temp_mime.ctype_is_rfc822())
		temp_mime.ctype = "message/rfc822";
	auto pnode = pjson->stree.get_root();
	if (NULL == pnode) {
		auto pmime = std::make_unique<MJSON_MIME>();
		pmime->stree.pdata = pmime.get();
		pmime->mime_type = mime_type::none;
		pjson->stree.set_root(std::move(pmime));
	}
	pnode = pjson->stree.get_root();
	if (pnode == nullptr)
		return FALSE;
	auto pmime = static_cast<MJSON_MIME *>(pnode->pdata);
	if (temp_mime.id.empty()) {
		if (pmime->get_mtype() != mime_type::none)
			return FALSE;
		temp_mime.stree = pmime->stree;
		*pmime = std::move(temp_mime);
		return TRUE;
	}
	temp_len = strlen(temp_mime.id.c_str());
	memcpy(temp_buff, temp_mime.id.c_str(), temp_len + 1);
	last_pos = 0;
	for (size_t i = 0; i <= temp_len; ++i) {
		if (temp_buff[i] != '.' && temp_buff[i] != '\0')
			continue;
		temp_buff[i] = '\0';
		int offset = strtol(temp_buff + last_pos, nullptr, 0);
		pnode = pmime->stree.get_child();
		if (NULL == pnode) {
			pnode = &pmime->stree;
			auto pmime_uq = std::make_unique<MJSON_MIME>();
			pmime = pmime_uq.get();
			pmime->stree.pdata = pmime;
			pmime->mime_type = mime_type::none;
			if (!pjson->stree.add_child(pnode, std::move(pmime_uq),
			    SIMPLE_TREE_ADD_LAST))
				return FALSE;
		} else {
			pmime = static_cast<MJSON_MIME *>(pnode->pdata);
		}

		for (j = 1; j < offset; j++) {
			pnode = pmime->stree.get_sibling();
			if (pnode != nullptr) {
				pmime = static_cast<MJSON_MIME *>(pnode->pdata);
				continue;
			}
			pnode = &pmime->stree;
			auto pmime_uq = std::make_unique<MJSON_MIME>();
			pmime = pmime_uq.get();
			pmime->stree.pdata = pmime;
			pmime->mime_type = mime_type::none;
			if (!pjson->stree.insert_sibling(pnode, std::move(pmime_uq),
			    SIMPLE_TREE_INSERT_AFTER))
				return FALSE;
		}
		last_pos = i + 1;
	}

	if (pmime->get_mtype() != mime_type::none)
		return FALSE;
	temp_mime.stree = pmime->stree;
	*pmime = std::move(temp_mime);
	return TRUE;
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

int MJSON::fetch_structure(const char *cset, BOOL b_ext, std::string &buf) const try
{
	auto pjson = this;
	auto pnode = pjson->stree.get_root();
	if (pnode == nullptr)
		return -1;
	auto pmime = static_cast<const MJSON_MIME *>(pnode->pdata);
	return mjson_fetch_mime_structure(pmime, nullptr, nullptr, cset,
	       charset.c_str(), b_ext, buf);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2061: ENOMEM");
	return -1;
}

static int mjson_fetch_mime_structure(const MJSON_MIME *pmime,
    const char *storage_path, const char *msg_filename, const char *charset,
    const char *email_charset, BOOL b_ext, std::string &buf) try
{
#ifdef _DEBUG_UMTA
	if (pmime == nullptr) {
		mlog(LV_DEBUG, "mail: NULL pointer in mjson_fetch_mime_structure");
		return -1;
	}
#endif
 FETCH_STRUCTURE_LOOP:
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
			struct stat node_stat;
			
			if (*msg_filename == '\0')
				temp_path = storage_path + "/"s + pmime->get_id();
			else
				temp_path = storage_path + "/"s + msg_filename + "." + pmime->get_id();
			buf += stat(temp_path.c_str(), &node_stat) == 0 ?
			       " " + std::to_string(node_stat.st_size) :
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
			size_t slurp_size = 0;
			std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_file(temp_path.c_str(), &slurp_size));
			if (slurp_data == nullptr)
				goto RFC822_FAILURE;
			Json::Value digest;
			if (!json_from_str({slurp_data.get(), slurp_size}, digest))
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
			auto body_len = mjson_rfc822_fetch_internal(&temp_mjson, storage_path,
						charset, b_ext, body);
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
		auto pnode = pmime->stree.get_child();
		if (pnode == nullptr)
			return -1;
		if (mjson_fetch_mime_structure(static_cast<const MJSON_MIME *>(pnode->pdata),
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

	auto pnode = pmime->stree.get_sibling();
	if (NULL != pnode) {
		pmime = static_cast<MJSON_MIME *>(pnode->pdata);
		goto FETCH_STRUCTURE_LOOP;
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

static void mjson_emum_rfc822(MJSON_MIME *input_mime, void *param)
{
	const MJSON_MIME *pmime = input_mime;
	auto pb_found = static_cast<BOOL *>(param);
	if (!*pb_found && pmime->ctype_is_rfc822())
		*pb_found = TRUE;
}

bool MJSON::has_rfc822_part() const
{
	BOOL b_found = false;
	const_cast<MJSON *>(this)->enum_mime(mjson_emum_rfc822, &b_found);
	return b_found;
}

static void mjson_enum_build(MJSON_MIME *input_mime, void *param) try
{
	const MJSON_MIME *pmime = input_mime;
	auto pbuild = static_cast<BUILD_PARAM *>(param);
	size_t length1;
	
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
		
	wrapfd fd = open(temp_path.c_str(), O_RDONLY);
	if (fd.get() < 0) {
		pbuild->build_result = FALSE;
		return;
	}
	
	auto length = pmime->get_content_length();
	std::unique_ptr<char[], stdlib_delete> pbuff(me_alloc<char>(strange_roundup(length - 1, 64 * 1024)));
	if (NULL == pbuff) {
		pbuild->build_result = FALSE;
		return;
	}
	if (lseek(fd.get(), pmime->get_content_offset(), SEEK_SET) < 0) {
		mlog(LV_ERR, "E-1430: lseek: %s", strerror(errno));
		pbuild->build_result = FALSE;
		return;
	}
	auto rdlen = ::read(fd.get(), pbuff.get(), length);
	if (rdlen < 0 || static_cast<size_t>(rdlen) != length) {
		pbuild->build_result = FALSE;
		return;
	}
	fd.close_rd();
	
	if (pmime->encoding_is_b()) {
		std::unique_ptr<char[], stdlib_delete> pbuff1(me_alloc<char>(strange_roundup(length - 1, 64 * 1024)));
		if (NULL == pbuff1) {
			pbuild->build_result = FALSE;
			return;
		}
		if (decode64_ex(pbuff.get(), length, pbuff1.get(), length, &length1) != 0) {
			pbuild->build_result = FALSE;
			return;
		}
		pbuff = std::move(pbuff1);
		length = length1;
	} else if (pmime->encoding_is_q()) {
		std::unique_ptr<char[], stdlib_delete> pbuff1(me_alloc<char>(strange_roundup(length - 1, 64 * 1024)));
		if (NULL == pbuff1) {
			pbuild->build_result = FALSE;
			return;
		}
		auto qdlen = qp_decode_ex(pbuff1.get(), length, pbuff.get(), length);
		if (qdlen < 0) {
			pbuild->build_result = false;
			return;
		}
		length = qdlen;
		pbuff = std::move(pbuff1);
	}
	
	MJSON temp_mjson;
	MAIL imail;
	if (!imail.load_from_str(pbuff.get(), length)) {
		pbuild->build_result = FALSE;
		return;
	}
	size_t mess_len;
	fd = open(msg_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, FMODE_PRIVATE);
	if (fd.get() < 0) {
		mlog(LV_ERR, "E-1767: open %s for write failed: %s", msg_path.c_str(), strerror(errno));
		pbuild->build_result = FALSE;
		return;
	}
	auto err = imail.to_fd(fd.get());
	if (err == 0)
		err = fd.close_wr();
	if (err != 0) {
		mlog(LV_ERR, "E-1768: write to %s failed: %s", msg_path.c_str(), strerror(err));
		fd.close_rd();
		if (::remove(msg_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1372: remove %s: %s", msg_path.c_str(), strerror(errno));
		pbuild->build_result = FALSE;
		return;
	}
	Json::Value digest;
	auto result = imail.make_digest(&mess_len, digest);
	imail.clear();
	pbuff.reset();
	if (result <= 0) {
		if (::remove(msg_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1373: remove %s: %s", msg_path.c_str(), strerror(errno));
		pbuild->build_result = FALSE;
		return;
	}
	if (pbuild->depth == 1)
		digest["file"] = pmime->get_id();
	else
		digest["file"] = std::string(pbuild->filename) + "." + pmime->get_id();
	auto djson = json_to_str(digest);
	fd = open(dgt_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, FMODE_PRIVATE);
	if (fd.get() < 0) {
		if (::remove(msg_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1374: remove %s: %s", msg_path.c_str(), strerror(errno));
		pbuild->build_result = FALSE;
		return;
	}
	if (HXio_fullwrite(fd.get(), djson.data(), djson.size()) < 0 ||
	    fd.close_wr() != 0) {
		mlog(LV_ERR, "E-2129: write %s: %s", dgt_path.c_str(), strerror(errno));
		fd.close_rd();
		if (::remove(dgt_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1375: remove %s: %s", dgt_path.c_str(), strerror(errno));
		if (::remove(msg_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1376: remove %s: %s", msg_path.c_str(), strerror(errno));
		pbuild->build_result = FALSE;
		return;
	}
	if (!temp_mjson.load_from_json(digest)) {
		if (::remove(dgt_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1377: remove %s: %s", dgt_path.c_str(), strerror(errno));
		if (::remove(msg_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1378: remove %s: %s", msg_path.c_str(), strerror(errno));
		pbuild->build_result = FALSE;
		return;
	}
	temp_mjson.path = pbuild->storage_path;
	
	if (pbuild->depth >= MAX_RFC822_DEPTH || !temp_mjson.has_rfc822_part())
		return;
	BUILD_PARAM build_param;
	build_param.filename = temp_mjson.get_mail_filename();
	build_param.msg_path = temp_mjson.path.c_str();
	build_param.storage_path = pbuild->storage_path;
	build_param.depth = pbuild->depth + 1;
	build_param.build_result = TRUE;

	temp_mjson.enum_mime(mjson_enum_build, &build_param);
	if (!build_param.build_result) {
		if (::remove(dgt_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1379: remove %s: %s", dgt_path.c_str(), strerror(errno));
		if (::remove(msg_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1380: remove %s: %s", msg_path.c_str(), strerror(errno));
		pbuild->build_result = FALSE;
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1138: ENOMEM");
}

BOOL MJSON::rfc822_build(const char *storage_path) const
{
	auto pjson = this;
	if (!has_rfc822_part())
		return FALSE;
	if (pjson->path.empty())
		return FALSE;
	auto temp_path = storage_path + "/"s + pjson->get_mail_filename();
	if (mkdir(temp_path.c_str(), 0777) != 0 && errno != EEXIST) {
		mlog(LV_ERR, "E-1433: mkdir %s: %s", temp_path.c_str(), strerror(errno));
		return FALSE;
	}
	BUILD_PARAM build_param;
	build_param.filename = pjson->get_mail_filename();
	build_param.msg_path = pjson->path.c_str();
	build_param.storage_path = temp_path.c_str();
	build_param.depth = 1;
	build_param.build_result = TRUE;
	const_cast<MJSON *>(pjson)->enum_mime(mjson_enum_build, &build_param);
	if (!build_param.build_result)
		rmdir(temp_path.c_str());
	return build_param.build_result;
}

BOOL MJSON::rfc822_get(MJSON *pjson, const char *storage_path, const char *id,
    char *mjson_id, char *mime_id) const try
{
	auto pjson_base = this;
	char *pdot;
	char temp_path[256];
	struct stat node_stat;

	if (!has_rfc822_part())
		return FALSE;
	snprintf(temp_path, std::size(temp_path), "%s/%s", storage_path,
	         pjson_base->get_mail_filename());
	if (stat(temp_path, &node_stat) != 0 || !S_ISDIR(node_stat.st_mode))
		return FALSE;
	
	snprintf(mjson_id, 64, "%s.", id);
	while (NULL != (pdot = strrchr(mjson_id, '.'))) {
		*pdot = '\0';
		char dgt_path[256];
		snprintf(dgt_path, std::size(dgt_path), "%s/%s/%s.dgt", storage_path,
		         pjson_base->get_mail_filename(), mjson_id);
		size_t slurp_size = 0;
		std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_file(dgt_path, &slurp_size));
		if (slurp_data == nullptr) {
			if (errno == ENOENT || errno == EISDIR)
				continue;
			return FALSE;
		}
		pjson->clear();
		Json::Value digest;
		if (!json_from_str({slurp_data.get(), slurp_size}, digest) ||
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
	
int MJSON::rfc822_fetch(const char *storage_path, const char *cset,
    BOOL b_ext, std::string &buf) const
{
	auto pjson = this;
	struct stat node_stat;

#ifdef _DEBUG_UMTA
	if (storage_path == nullptr) {
		mlog(LV_DEBUG, "mail: NULL pointer in mjson_rfc822_fetch");
		return -1;
	}
#endif
	if (!has_rfc822_part())
		return -1;
	auto temp_path = storage_path + "/"s + get_mail_filename();
	if (stat(temp_path.c_str(), &node_stat) != 0 || !S_ISDIR(node_stat.st_mode))
		return -1;
	auto pnode = pjson->stree.get_root();
	if (pnode == nullptr)
		return -1;
	auto pmime = static_cast<const MJSON_MIME *>(pnode->pdata);
	return mjson_fetch_mime_structure(pmime, temp_path.c_str(), "", cset,
	       pjson->charset.c_str(), b_ext, buf);
}

static int mjson_rfc822_fetch_internal(const MJSON *pjson, const char *storage_path,
    const char *charset, BOOL b_ext, std::string &buf)
{
#ifdef _DEBUG_UMTA
	if (pjson == nullptr || storage_path == nullptr) {
		mlog(LV_DEBUG, "mail: NULL pointer in mjson_rfc822_fetch_internal");
		return -1;
	}
#endif
	auto pnode = pjson->stree.get_root();
	if (pnode == nullptr)
		return -1;
	auto pmime = static_cast<const MJSON_MIME *>(pnode->pdata);
	return mjson_fetch_mime_structure(pmime, storage_path,
	       pjson->get_mail_filename(), charset,
	       pjson->charset.c_str(), b_ext, buf);
}
