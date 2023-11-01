// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <libHX/ctype_helper.h>
#include <libHX/defs.h>
#include <libHX/io.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/json.hpp>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mjson.hpp>
#include <gromox/util.hpp>
#define MAX_RFC822_DEPTH	5

#define MAX_DIGLEN			256*1024

#define DEF_MODE			S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

using namespace gromox;

enum {
	TYPE_STRUCTURE,
	TYPE_MIMES
};

namespace {

struct ENUM_PARAM {
	const char *id;
	MJSON_MIME *pmime;
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
static int mjson_fetch_mime_structure(MJSON_MIME *pmime,
	const char *storage_path, const char *msg_filename, const char* charset,
	const char *email_charset, BOOL b_ext, char *buff, int length);
static int mjson_convert_address(const char *address, const char *charset, char *buff, int length);
static void mjson_add_backslash(const char *astring, char *out_string);
static void mjson_emum_rfc822(MJSON_MIME *, void *);
static void mjson_enum_build(MJSON_MIME *, void *);
static int mjson_rfc822_fetch_internal(MJSON *pjson, const char *storage_path,
	const char *charset, BOOL b_ext, char *buff, int length);

alloc_limiter<MJSON_MIME> mjson_allocator_init(size_t max_size,
    const char *name, const char *hint)
{
	return alloc_limiter<MJSON_MIME>(max_size, name, hint);
}

/*
 *	@param
 *		pjson [in]			indicate the mjson object
 *		ppool [in]		    indicate the allocator for mime object
 */
MJSON::MJSON(alloc_limiter<MJSON_MIME> *p) : ppool(p)
{
#ifdef _DEBUG_UMTA
	if (p == nullptr)
		throw std::invalid_argument("[mail]: NULL pointer in mjson_init");
#endif
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
	auto pnode = pjson->tree.get_root();
	if (pnode != nullptr)
		pjson->tree.destroy_node(pnode, mjson_enum_delete);
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
	auto m = static_cast<MJSON_MIME *>(pnode->pdata);
	m->ppool->put(m);
}

MJSON::~MJSON()
{
	clear();
	tree.clear();
}

/*
 *	retrieve mjson object from mail digest string
 *	@param
 *		pjson [in]			indicate the mjson object
 *		digest_buff[in]		mail digest string buffer
 *		length				string buffer length
 *		path [in]			mail file path, can be NULL.
 *                          if you want to build rfc822
 *                          or seek file descriptor in
 *                          message, path cannot be NULL.
 */
BOOL MJSON::load_from_json(const Json::Value &root, const char *inpath) try
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
	auto pnode = pjson->tree.get_root();
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
	if (inpath != nullptr)
		pjson->path = inpath;
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
	auto r = pjson->tree.get_root();
	if (r == nullptr)
		return;
	simple_tree_enum_from_node(r, [&](tree_node *stn, unsigned int) {
		auto m = containerof(stn, MJSON_MIME, stree);
		enum_func(m, param);
	});
}

size_t MJSON_MIME::get_length(unsigned int param) const
{
	auto pmime = this;
	switch (param) {
	case MJSON_MIME_HEAD:
		return (pmime->begin - pmime->head);
	case MJSON_MIME_CONTENT:
		return pmime->length;
	case MJSON_MIME_ENTIRE:
		return (pmime->begin + pmime->length - pmime->head);
	default:
		return 0;
	}
}

size_t MJSON_MIME::get_offset(unsigned int param) const
{
	auto pmime = this;
	switch (param) {
	case MJSON_MIME_HEAD:
		return pmime->head;
	case MJSON_MIME_CONTENT:
		return pmime->begin;
	default:
		return 0;
	}
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
MJSON_MIME *MJSON::get_mime(const char *id)
{
	ENUM_PARAM enum_param = {id};
	simple_tree_enum_from_node(tree.get_root(), [&](const tree_node *nd, unsigned int) {
		if (enum_param.pmime != nullptr)
			return;
		auto m = static_cast<MJSON_MIME *>(nd->pdata);
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
	
	temp_mime.ppool = pjson->ppool;
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
	if (strtailcase(temp_mime.filename.c_str(), ".eml") == 0 &&
	    !temp_mime.ctype_is_rfc822())
		temp_mime.ctype = "message/rfc822";
	auto pnode = pjson->tree.get_root();
	if (NULL == pnode) {
		auto pmime = pjson->ppool->get();
		pmime->stree.pdata = pmime;
		pmime->ppool = pjson->ppool;
		pmime->mime_type = mime_type::none;
		pjson->tree.set_root(&pmime->stree);
	}
	pnode = pjson->tree.get_root();
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
			pmime = pjson->ppool->get();
			pmime->stree.pdata = pmime;
			pmime->ppool = pjson->ppool;
			pmime->mime_type = mime_type::none;
			if (!pjson->tree.add_child(
			    pnode, &pmime->stree, SIMPLE_TREE_ADD_LAST)) {
				pjson->ppool->put(pmime);
				return FALSE;
			}
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
			pmime = pjson->ppool->get();
			pmime->stree.pdata = pmime;
			pmime->ppool = pjson->ppool;
			pmime->mime_type = mime_type::none;
			if (!pjson->tree.insert_sibling(pnode,
			    &pmime->stree, SIMPLE_TREE_INSERT_AFTER)) {
				pjson->ppool->put(pmime);
				return FALSE;
			}
		}
		last_pos = i + 1;
	}

	if (pmime->get_mtype() != mime_type::none)
		return FALSE;
	temp_mime.stree = pmime->stree;
	*pmime = std::move(temp_mime);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2185: ENOMEM");
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

int MJSON::fetch_structure(const char *cset, BOOL b_ext, char *buff,
    int length) try
{
	auto pjson = this;

#ifdef _DEBUG_UMTA
	if (buff == nullptr) {
		mlog(LV_DEBUG, "mail: NULL pointer in mjson_fetch_structure");
		return -1;
	}
#endif
	auto pnode = pjson->tree.get_root();
	if (pnode == nullptr)
		return -1;
	auto pmime = static_cast<MJSON_MIME *>(pnode->pdata);
	auto ret_len = mjson_fetch_mime_structure(pmime, nullptr, nullptr, cset,
	               pjson->charset.c_str(), b_ext, buff, length);
	if (ret_len == -1)
		return -1;
	buff[ret_len] = '\0';
	return ret_len;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2186: ENOMEM");
	return -1;
}

static bool mjson_is_asciipr(const char *s)
{
	return std::all_of(s, s + strlen(s),
	       [](unsigned char c) { return isascii(c) && isprint(c); });
}

static int mjson_fetch_mime_structure(MJSON_MIME *pmime,
    const char *storage_path, const char *msg_filename, const char *charset,
    const char *email_charset, BOOL b_ext, char *buff, int length) try
{
	int offset;
	BOOL b_space;
	size_t ecode_len;
	char temp_buff[2048];

#ifdef _DEBUG_UMTA
	if (NULL == pmime || NULL == buff) {
		mlog(LV_DEBUG, "mail: NULL pointer in mjson_fetch_mime_structure");
		return -1;
	}
#endif
	
	offset = 0;
	
 FETCH_STRUCTURE_LOOP:
	auto ctype = pmime->ctype;
	HX_strupper(ctype.data());
	auto psubtype = strchr(ctype.data(), '/');
	if (psubtype == nullptr)
		psubtype = deconst("NIL");
	else
		*psubtype++ = '\0';
	
	if (pmime->get_mtype() == mime_type::single ||
	    pmime->get_mtype() == mime_type::single_obj) {
		offset += gx_snprintf(buff + offset, length - offset,
		          "(\"%s\" \"%s\"", ctype.c_str(), psubtype);
		if (*pmime->get_charset() != '\0' || *pmime->get_filename() != '\0') {
			buff[offset++] = ' ';
			buff[offset++] = '(';
			b_space = FALSE;
			if (*pmime->get_charset() != '\0') {
				offset += gx_snprintf(buff + offset, length - offset,
				          "\"CHARSET\" \"%s\"", pmime->get_charset());
				b_space = TRUE;
			} else if (strcasecmp(ctype.c_str(), "text") == 0 &&
			    *email_charset != '\0') {
				offset += gx_snprintf(buff + offset, length - offset,
						"\"CHARSET\" \"%s\"", email_charset);
				b_space = TRUE;
			}
			
			if (*pmime->get_filename() != '\0') {
				if (b_space)
					buff[offset++] = ' ';
				if (mjson_is_asciipr(pmime->get_filename())) {
					mjson_add_backslash(pmime->get_filename(), temp_buff);
					offset += gx_snprintf(buff + offset, length - offset,
								"\"NAME\" \"%s\"", temp_buff);
				} else {
					offset += gx_snprintf(buff + offset, length - offset,
								"\"NAME\" \"=?%s?b?",
								('\0' != email_charset[0])?email_charset:charset);
					if (encode64(pmime->get_filename(), strlen(pmime->get_filename()),
					    &buff[offset], length - offset, &ecode_len) != 0)
						return -1;
					offset += ecode_len;
					memcpy(buff + offset, "?=\"", 3);
					offset += 3;
				}
			}
			
			buff[offset++] = ')';
		} else {
			memcpy(buff + offset, " NIL", 4);
			offset += 4;
		}
		
		if (pmime->cid.size() > 0 &&
		    mjson_is_asciipr(pmime->cid.c_str())) {
			mjson_add_backslash(pmime->cid.c_str(), temp_buff);
			offset += gx_snprintf(buff + offset, length - offset,
						" \"%s\"", temp_buff);
		} else {
			memcpy(buff + offset, " NIL", 4);
			offset += 4;
		}
		
		/* body description */
		memcpy(buff + offset, " NIL", 4);
		offset += 4;
		
		if (*pmime->get_encoding() == '\0') {
			memcpy(buff + offset, " NIL", 4);
			offset += 4;
		} else if (storage_path != nullptr && msg_filename != nullptr &&
		    pmime->ctype_is_rfc822()) {
			/* revision for APPLE device */
			if (pmime->encoding_is_b() ||
			    pmime->encoding_is_q())
				offset += gx_snprintf(buff + offset, length - offset,
				          " \"7bit\"");
			else
				offset += gx_snprintf(buff + offset, length - offset,
				          " \"%s\"", pmime->get_encoding());
		} else {
			offset += gx_snprintf(buff + offset, length - offset,
			          " \"%s\"", pmime->get_encoding());
		}
		
		if (NULL != storage_path && NULL != msg_filename &&
		    pmime->ctype_is_rfc822() &&
		    (pmime->encoding_is_b() || pmime->encoding_is_q())) {
			char temp_path[256];
			struct stat node_stat;
			
			if ('\0' == msg_filename[0]) {
				snprintf(temp_path, 256, "%s/%s", storage_path,
				         pmime->get_id());
			} else {
				snprintf(temp_path, 256, "%s/%s.%s", storage_path,
				         msg_filename, pmime->get_id());
			}
			
			if (0 == stat(temp_path, &node_stat)) {
				offset += gx_snprintf(buff + offset, length - offset,
				          " %llu", static_cast<unsigned long long>(node_stat.st_size));
			} else {
				memcpy(buff + offset, " NIL", 4);
				offset += 4;
			}
		} else {
			offset += gx_snprintf(buff + offset, length - offset,
			          " %zu", pmime->length);
		}
					
		if (strcasecmp(ctype.c_str(), "TEXT") == 0) {
			/* body lines */
			memcpy(buff + offset, " NIL", 4);
			offset += 4;
		}
		
		if (NULL != storage_path && NULL != msg_filename &&
		    pmime->ctype_is_rfc822()) {
			int envl_len;
			int body_len;
			char temp_path[256];
			
			if (*msg_filename == '\0')
				snprintf(temp_path, 256, "%s/%s.dgt", storage_path,
				         pmime->get_id());
			else
				snprintf(temp_path, 256, "%s/%s.%s.dgt", storage_path,
				         msg_filename, pmime->get_id());
			size_t slurp_size = 0;
			std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_file(temp_path, &slurp_size));
			if (slurp_data == nullptr)
				goto RFC822_FAILURE;
			Json::Value digest;
			if (!json_from_str({slurp_data.get(), slurp_size}, digest))
				goto RFC822_FAILURE;
			MJSON temp_mjson(pmime->ppool);
			if (!temp_mjson.load_from_json(digest, storage_path))
				goto RFC822_FAILURE;
			buff[offset] = ' ';
			envl_len = temp_mjson.fetch_envelope(charset,
						buff + offset + 1, length - offset - 1);
			if (envl_len == -1)
				goto RFC822_FAILURE;
			
			buff[offset + 1 + envl_len] = ' ';
			
			body_len = mjson_rfc822_fetch_internal(&temp_mjson, storage_path,
						charset, b_ext, buff + offset + envl_len + 2,
						length - offset - envl_len - 2);
			if (body_len == -1)
				goto RFC822_FAILURE;
			offset += envl_len + body_len + 2;
			goto RFC822_SUCCESS;
		}
		
 RFC822_FAILURE:
		if (b_ext) {
			/* body MD5 */
			
			
			memcpy(buff + offset, " NIL", 4);
			offset += 4;
			if (pmime->cntdspn.size() > 0) {
				offset += gx_snprintf(buff + offset, length - offset,
				          " (\"%s\" NIL)", pmime->cntdspn.c_str());
			} else {
				memcpy(buff + offset, " NIL", 4);
				offset += 4;
			}
			
			/* body language */
			
			memcpy(buff + offset, " NIL", 4);
			offset += 4;
			if (pmime->cntl.size() > 0 &&
			    mjson_is_asciipr(pmime->cntl.c_str())) {
				mjson_add_backslash(pmime->cntl.c_str(), temp_buff);
				offset += gx_snprintf(buff + offset, length - offset,
							" \"%s\"", temp_buff);
			} else {
				memcpy(buff + offset, " NIL", 4);
				offset += 4;
			}
		}
		
 RFC822_SUCCESS:
		buff[offset++] = ')';
	} else if (pmime->get_mtype() == mime_type::multiple) {
		buff[offset++] = '(';
		auto pnode = pmime->stree.get_child();
		if (pnode == nullptr)
			return -1;
		auto ret_len = mjson_fetch_mime_structure(static_cast<MJSON_MIME *>(pnode->pdata),
					storage_path, msg_filename, charset, email_charset,
					b_ext, buff + offset, length - offset);
		if (ret_len == -1)
			return -1;
		offset += ret_len;
		offset += gx_snprintf(buff + offset, length - offset,
					" \"%s\"", psubtype);
		if (b_ext) {
			memcpy(buff + offset, " NIL NIL NIL", 12);
			offset += 12;
		}
		buff[offset++] = ')';
	} else {
		return -1;
	}

	auto pnode = pmime->stree.get_sibling();
	if (NULL != pnode) {
		pmime = static_cast<MJSON_MIME *>(pnode->pdata);
		goto FETCH_STRUCTURE_LOOP;
	}
	return offset >= length ? -1 : offset;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1322: ENOMEM");
	return -1;
}

static int mjson_convert_address(const char *address, const char *charset,
    char *buff, int length)
{
	int offset;
	size_t ecode_len;
	EMAIL_ADDR email_addr;
	char temp_buff[2048];
	
	offset = 0;
	parse_mime_addr(&email_addr, address);
	if (*email_addr.display_name == '\0') {
		memcpy(buff + offset, "(NIL", 4);
		offset += 4;
	} else if (mjson_is_asciipr(email_addr.display_name)) {
		mjson_add_backslash(email_addr.display_name, temp_buff);
		offset += gx_snprintf(buff + offset, length - offset,
		          "(\"%s\"", temp_buff);
	} else {
		/*
		 * qp_encode_ex is only suitable for bodytext but not
		 * encoded-words, so just pick base64
		 */
		offset += gx_snprintf(buff + offset, length - offset, "(\"=?utf-8?b?");
		if (encode64(email_addr.display_name,
		    strlen(email_addr.display_name), buff + offset,
		    length - offset, &ecode_len) != 0)
			return -1;
		offset += ecode_len;
		memcpy(buff + offset, "?=\"", 3);
		offset += 3;
	}
	
	/* at-domain-list */
	memcpy(buff + offset, " NIL", 4);
	offset += 4;
	
	if ('\0' != email_addr.local_part[0] &&
	    mjson_is_asciipr(email_addr.local_part)) {
		mjson_add_backslash(email_addr.local_part, temp_buff);
		offset += gx_snprintf(buff + offset, length - offset,
					" \"%s\"", temp_buff);
	} else {
		memcpy(buff + offset, " NIL", 4);
		offset += 4;
	}

	if ('\0' != email_addr.domain[0] &&
	    mjson_is_asciipr(email_addr.domain)) {
		mjson_add_backslash(email_addr.domain, temp_buff);
		offset += gx_snprintf(buff + offset, length - offset,
					" \"%s\")", temp_buff);
	} else {
		memcpy(buff + offset, " NIL)", 5);
		offset += 5;
	}
	return offset >= length ? -1 : offset;
}

int MJSON::fetch_envelope(const char *cset, char *buff, int length)
{
	auto pjson = this;
	int offset, tmp_len, last_pos;
	size_t ecode_len;
	BOOL b_quoted;
	BOOL b_bracket;
	char temp_buff[2048];


#ifdef _DEBUG_UMTA
	if (NULL == pjson || NULL == buff) {
		mlog(LV_DEBUG, "mail: NULL pointer in mjson_fetch_envelope");
		return -1;
	}
#endif
	
	
	buff[0] = '(';
	offset = 1;
	if (pjson->date.size() > 0 &&
	    mjson_is_asciipr(pjson->date.c_str())) {
		mjson_add_backslash(pjson->date.c_str(), temp_buff);
		offset += gx_snprintf(buff + offset, length - offset,
					"\"%s\"", temp_buff);
	} else {
		memcpy(buff + offset, "NIL", 3);
		offset += 3;
	}
	
	if (pjson->subject.size() == 0) {
		memcpy(buff + offset, " NIL", 4);
		offset += 4;
	} else if (mjson_is_asciipr(pjson->subject.c_str())) {
		mjson_add_backslash(pjson->subject.c_str(), temp_buff);
		offset += gx_snprintf(buff + offset, length - offset,
		          " \"%s\"", temp_buff);
	} else {
		offset += gx_snprintf(buff + offset, length - offset, " \"=?%s?b?",
		          pjson->charset.size() > 0 ? pjson->charset.c_str() : cset);
		if (encode64(pjson->subject.c_str(), pjson->subject.size(),
		    &buff[offset], length - offset, &ecode_len) != 0)
			return -1;
		offset += ecode_len;
		memcpy(buff + offset, "?=\"", 3);
		offset += 3;
	}
	
	buff[offset++] = ' ';
	buff[offset++] = '(';
	auto ret_len = mjson_convert_address(pjson->from.c_str(), charset.c_str(),
	               &buff[offset], length - offset);
	if (ret_len == -1)
		return -1;
	offset += ret_len;
	buff[offset++] = ')';
	buff[offset++] = ' ';
	buff[offset++] = '(';
	ret_len = mjson_convert_address(pjson->sender.size() > 0 ?
	          pjson->sender.c_str() : pjson->from.c_str(), charset.c_str(),
	          &buff[offset], length - offset);
	if (ret_len == -1)
		return -1;
	offset += ret_len;
	buff[offset++] = ')';
	buff[offset++] = ' ';
	buff[offset++] = '(';
	ret_len = mjson_convert_address(pjson->reply.size() > 0 ?
	          pjson->reply.c_str() : pjson->from.c_str(), charset.c_str(),
	          &buff[offset], length - offset);
	if (ret_len == -1)
		return -1;
	offset += ret_len;
	buff[offset++] = ')';
	
	auto len = pjson->to.size();
	last_pos = 0;
	b_quoted = FALSE;
	b_bracket = FALSE;
	for (size_t i = 0; i <= len; ++i) {
		if ('"' == pjson->to[i]) {
			b_quoted = b_quoted?FALSE:TRUE;
		} else if (',' == pjson->to[i] || ';' == pjson->to[i] ||
			'\0' == pjson->to[i]) {
			tmp_len = i - last_pos;
			if (!b_quoted && tmp_len < 1024 && tmp_len > 0) {
				buff[offset++] = ' ';
				if (!b_bracket) {
					buff[offset++] = '(';
					b_bracket = TRUE;
				}
				memcpy(temp_buff, &pjson->to[last_pos], tmp_len);
				temp_buff[tmp_len] = '\0';
				ret_len = mjson_convert_address(temp_buff, charset.c_str(),
				          &buff[offset], length - offset);
				if (ret_len == -1)
					return -1;
				offset += ret_len;
				last_pos = i + 1;
			}
		}
	}
	
	if (!b_bracket) {
		memcpy(buff + offset, " NIL", 4);
		offset += 4;
	} else {
		buff[offset++] = ')';
	}
	
	len = pjson->cc.size();
	last_pos = 0;
	b_quoted = FALSE;
	b_bracket = FALSE;
	for (size_t i = 0; i <= len; ++i) {
		if ('"' == pjson->cc[i]) {
			b_quoted = b_quoted?FALSE:TRUE;
		} else if (',' == pjson->cc[i] || ';' == pjson->cc[i] ||
			'\0' == pjson->cc[i]) {
			tmp_len = i - last_pos;
			if (!b_quoted && tmp_len < 1024 && tmp_len > 0) {
				buff[offset++] = ' ';
				if (!b_bracket) {
					buff[offset++] = '(';
					b_bracket = TRUE;
				}
				memcpy(temp_buff, &pjson->cc[last_pos], tmp_len);
				temp_buff[tmp_len] = '\0';
				ret_len = mjson_convert_address(temp_buff, charset.c_str(),
				          &buff[offset], length - offset);
				if (ret_len == -1)
					return -1;
				offset += ret_len;
				last_pos = i + 1;
			}
		}
	}
	
	if (!b_bracket) {
		memcpy(buff + offset, " NIL", 4);
		offset += 4;
	} else {
		buff[offset++] = ')';
	}
	
	/* bcc */
	memcpy(buff + offset, " NIL", 4);
	offset += 4;
	if (pjson->inreply.size() > 0 &&
	    mjson_is_asciipr(pjson->inreply.c_str())) {
		mjson_add_backslash(pjson->inreply.c_str(), temp_buff);
		offset += gx_snprintf(buff + offset, length - offset,
					" \"%s\"", temp_buff);
	} else {
		memcpy(buff + offset, " NIL", 4);
		offset += 4;
	}
	
	if (*pjson->get_mail_messageid() != '\0' &&
	    mjson_is_asciipr(pjson->get_mail_messageid())) {
		mjson_add_backslash(pjson->get_mail_messageid(), temp_buff);
		offset += gx_snprintf(buff + offset, length - offset,
					" \"%s\"", temp_buff);
	} else {
		memcpy(buff + offset, " NIL", 4);
		offset += 4;
	}
	
	buff[offset++] = ')';
	buff[offset] = '\0';
	return offset >= length ? -1 : offset;
}

static void mjson_add_backslash(const char *astring, char *out_string)
{
	int i, j, len;
	
	len = strlen(astring) + 1;
	
	for (i=0,j=0; i<len; i++,j++) {
		if (astring[i] == '"' || astring[i] == '\\')
			out_string[j++] = '\\';
		out_string[j] = astring[i];
	}
}

static void mjson_emum_rfc822(MJSON_MIME *pmime, void *param)
{
	auto pb_found = static_cast<BOOL *>(param);
	if (!*pb_found && pmime->ctype_is_rfc822())
		*pb_found = TRUE;
}

BOOL MJSON::rfc822_check()
{
	BOOL b_found = false;
	enum_mime(mjson_emum_rfc822, &b_found);
	return b_found;
}

static void mjson_enum_build(MJSON_MIME *pmime, void *param) try
{
	auto pbuild = static_cast<BUILD_PARAM *>(param);
	size_t length1;
	char msg_path[256];
	char dgt_path[256];
	char temp_path[256];
	
	if (!pbuild->build_result || pbuild->depth > MAX_RFC822_DEPTH ||
	    !pmime->ctype_is_rfc822())
		return;
	
	snprintf(temp_path, 256, "%s/%s", pbuild->msg_path, pbuild->filename);
	if (1 == pbuild->depth) {
		snprintf(msg_path, std::size(msg_path), "%s/%s",
		         pbuild->storage_path, pmime->get_id());
		snprintf(dgt_path, std::size(dgt_path), "%s/%s.dgt",
		         pbuild->storage_path, pmime->get_id());
	} else {
		snprintf(msg_path, 256, "%s/%s.%s", pbuild->storage_path,
		         pbuild->filename, pmime->get_id());
		snprintf(dgt_path, 256, "%s/%s.%s.dgt", pbuild->storage_path,
		         pbuild->filename, pmime->get_id());
	}
		
	wrapfd fd = open(temp_path, O_RDONLY);
	if (fd.get() < 0) {
		pbuild->build_result = FALSE;
		return;
	}
	
	auto length = pmime->get_length(MJSON_MIME_CONTENT);
	std::unique_ptr<char[], stdlib_delete> pbuff(me_alloc<char>(strange_roundup(length - 1, 64 * 1024)));
	if (NULL == pbuff) {
		pbuild->build_result = FALSE;
		return;
	}
	if (lseek(fd.get(), pmime->get_offset(MJSON_MIME_CONTENT), SEEK_SET) < 0) {
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
	
	MJSON temp_mjson(pmime->ppool);
	MAIL imail;
	if (!imail.load_from_str_move(pbuff.get(), length)) {
		pbuild->build_result = FALSE;
		return;
	}
	/* for saving stacking size, so use C++
		style of local variable declaration */
	size_t mess_len;
	fd = open(msg_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (fd.get() < 0) {
		pbuild->build_result = FALSE;
		return;
	}
	if (!imail.to_file(fd.get()) || fd.close_wr() != 0) {
		fd.close_rd();
		if (remove(msg_path) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1372: remove %s: %s", msg_path, strerror(errno));
		pbuild->build_result = FALSE;
		return;
	}
	Json::Value digest;
	auto result = imail.get_digest(&mess_len, digest);
	imail.clear();
	pbuff.reset();
	if (result <= 0) {
		if (remove(msg_path) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1373: remove %s: %s", msg_path, strerror(errno));
		pbuild->build_result = FALSE;
		return;
	}
	if (pbuild->depth == 1)
		digest["file"] = pmime->get_id();
	else
		digest["file"] = std::string(pbuild->filename) + "." + pmime->get_id();
	auto djson = json_to_str(digest);
	fd = open(dgt_path, O_CREAT | O_TRUNC | O_WRONLY, DEF_MODE);
	if (fd.get() < 0) {
		if (remove(msg_path) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1374: remove %s: %s", msg_path, strerror(errno));
		pbuild->build_result = FALSE;
		return;
	}
	auto wr_ret = HXio_fullwrite(fd.get(), djson.data(), djson.size());
	if (wr_ret < 0 || fd.close_wr() != 0) {
		mlog(LV_ERR, "E-1333: write %s: %s", dgt_path, strerror(errno));
		fd.close_rd();
		if (remove(dgt_path) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1375: remove %s: %s", dgt_path, strerror(errno));
		if (remove(msg_path) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1376: remove %s: %s", msg_path, strerror(errno));
		pbuild->build_result = FALSE;
		return;
	}
	if (!temp_mjson.load_from_json(digest, pbuild->storage_path)) {
		if (remove(dgt_path) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1377: remove %s: %s", dgt_path, strerror(errno));
		if (remove(msg_path) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1378: remove %s: %s", msg_path, strerror(errno));
		pbuild->build_result = FALSE;
		return;
	}
	
	if (pbuild->depth >= MAX_RFC822_DEPTH || !temp_mjson.rfc822_check())
		return;
	BUILD_PARAM build_param;
	build_param.filename = temp_mjson.get_mail_filename();
	build_param.msg_path = temp_mjson.path.c_str();
	build_param.storage_path = pbuild->storage_path;
	build_param.depth = pbuild->depth + 1;
	build_param.build_result = TRUE;

	temp_mjson.enum_mime(mjson_enum_build, &build_param);
	if (!build_param.build_result) {
		if (remove(dgt_path) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1379: remove %s: %s", dgt_path, strerror(errno));
		if (remove(msg_path) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1380: remove %s: %s", msg_path, strerror(errno));
		pbuild->build_result = FALSE;
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1138: ENOMEM");
}

BOOL MJSON::rfc822_build(const char *storage_path)
{
	auto pjson = this;
	char temp_path[256];
	
	if (!rfc822_check())
		return FALSE;
	if (pjson->path.empty())
		return FALSE;
	
	snprintf(temp_path, std::size(temp_path), "%s/%s", storage_path,
	         pjson->get_mail_filename());
	if (mkdir(temp_path, 0777) != 0 && errno != EEXIST) {
		mlog(LV_ERR, "E-1433: mkdir %s: %s", temp_path, strerror(errno));
		return FALSE;
	}
	BUILD_PARAM build_param;
	build_param.filename = pjson->get_mail_filename();
	build_param.msg_path = pjson->path.c_str();
	build_param.storage_path = temp_path;
	build_param.depth = 1;
	build_param.build_result = TRUE;
	pjson->enum_mime(mjson_enum_build, &build_param);
	if (!build_param.build_result)
		rmdir(temp_path);
	return build_param.build_result;
}

BOOL MJSON::rfc822_get(MJSON *pjson, const char *storage_path, const char *id,
    char *mjson_id, char *mime_id) try
{
	auto pjson_base = this;
	char *pdot;
	char temp_path[256];
	struct stat node_stat;

	if (!rfc822_check())
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
		    !pjson->load_from_json(digest, temp_path))
			return false;
		strcpy(mime_id, pdot + 1);
		return TRUE;
	}
	return FALSE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1321: ENOMEM");
	return false;
}
	
int MJSON::rfc822_fetch(const char *storage_path, const char *cset,
    BOOL b_ext, char *buff, int length)
{
	auto pjson = this;
	char temp_path[256];
	struct stat node_stat;

#ifdef _DEBUG_UMTA
	if (storage_path == nullptr || buff == nullptr) {
		mlog(LV_DEBUG, "mail: NULL pointer in mjson_rfc822_fetch");
		return -1;
	}
#endif
	if (!rfc822_check())
		return FALSE;
	snprintf(temp_path, std::size(temp_path), "%s/%s", storage_path,
	         pjson->get_mail_filename());
	if (stat(temp_path, &node_stat) != 0 || !S_ISDIR(node_stat.st_mode))
		return FALSE;
	auto pnode = pjson->tree.get_root();
	if (pnode == nullptr)
		return -1;
	auto pmime = static_cast<MJSON_MIME *>(pnode->pdata);
	auto ret_len = mjson_fetch_mime_structure(pmime, temp_path, "", cset,
	               pjson->charset.c_str(), b_ext, buff, length);
	if (ret_len == -1)
		return -1;
	buff[ret_len] = '\0';
	return ret_len;
}

static int mjson_rfc822_fetch_internal(MJSON *pjson, const char *storage_path,
	const char *charset, BOOL b_ext, char *buff, int length)
{
#ifdef _DEBUG_UMTA
	if (NULL == pjson || NULL == storage_path || NULL == buff) {
		mlog(LV_DEBUG, "mail: NULL pointer in mjson_rfc822_fetch_internal");
		return -1;
	}
#endif
	auto pnode = pjson->tree.get_root();
	if (pnode == nullptr)
		return -1;
	auto pmime = static_cast<MJSON_MIME *>(pnode->pdata);
	auto ret_len = mjson_fetch_mime_structure(pmime, storage_path,
	               pjson->get_mail_filename(), charset,
	               pjson->charset.c_str(), b_ext, buff, length);
	if (ret_len == -1)
		return -1;
	buff[ret_len] = '\0';
	return ret_len;
}
