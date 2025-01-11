// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstring>
#include <memory>
#include <utility>
#include <libHX/defs.h>
#include <libHX/io.h>
#include <libHX/string.h>
#include <gromox/fileio.h>
#include <gromox/json.hpp>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>

using namespace gromox;

enum {
	TAG_SIGNED,
	TAG_ENCRYPT,
	TAG_NUM
};

static bool mail_retrieve_to_mime(MAIL *, MIME *parent, const char *begin, const char *end);
static void mail_enum_text_mime_charset(const MIME *, void *);
static void mail_enum_html_charset(const MIME *, void *);

void MAIL::clear()
{
	auto pmail = this;
	auto pnode = pmail->tree.get_root();
	if (pnode != nullptr)
		pmail->tree.destroy_node(pnode, [](SIMPLE_TREE_NODE *n) { delete static_cast<MIME *>(n->pdata); });
	if (NULL != pmail->buffer) {
		free(pmail->buffer);
		pmail->buffer = NULL;
	}
}

/*
 *	retrieve buffer into mail object
 *	@param
 *		pmail [in]			indicate the mail object
 *		in_buff [in]		buffer contains mail content
 *		length				indicate the buffer length
 *	@return
 *		TRUE				OK
 *		FALSE				fail
 */
bool MAIL::load_from_str(const char *in_buff, size_t length)
{
	auto pmail = this;

#ifdef _DEBUG_UMTA
	if (in_buff == nullptr) {
		mlog(LV_DEBUG, "NULL pointer in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	clear();
	auto mime_uq = MIME::create();
	auto pmime = mime_uq.get();
	if (NULL == pmime) {
		mlog(LV_ERR, "mail: MIME pool exhausted (too many parts in mail)");
		return false;
	}
	if (!pmime->load_from_str(nullptr, in_buff, length))
		return false;

	if (pmime->mime_type == mime_type::none) {
		mlog(LV_DEBUG, "mail: fatal error in %s", __PRETTY_FUNCTION__);
		return false;
	}
	pmail->tree.set_root(std::move(mime_uq));
	if (pmime->mime_type != mime_type::multiple)
		return true;
	auto fss = &pmime->first_boundary[pmime->boundary_len+2];
	auto nl_len = newline_size(fss, pmime->last_boundary - fss);
	if (mail_retrieve_to_mime(pmail, pmime, &fss[nl_len], pmime->last_boundary))
		return true;

	pmail->clear();
	/* retrieve as single mail object */
	mime_uq = MIME::create();
	pmime = mime_uq.get();
	if (NULL == pmime) {
		mlog(LV_ERR, "mail: MIME pool exhausted (too many parts in mail)");
		return false;
	}
	if (!pmime->load_from_str(nullptr, in_buff, length))
		return false;
	pmime->mime_type = mime_type::single;
	pmail->tree.set_root(std::move(mime_uq));
	return true;
}

/*
 *	recursive function for parsing mime
 *	@param
 *		pmail [in]			indicate the mail object
 *		pmime_parent [in]	mime of the parent node
 *		ptr_begin [in]		begin of multiple mime content
 *		ptr_end [in]		end of multiple mime content
 *	@return
 *		TRUE				OK
 *		FALSE				fail
 */
static bool mail_retrieve_to_mime(MAIL *pmail, MIME *pmime_parent,
    const char *ptr_begin, const char *ptr_end)
{
	std::unique_ptr<MIME> mime_uq;
	MIME *pmime, *pmime_last = nullptr;
	const char *ptr, *ptr_last = ptr_begin;

	for (ptr = ptr_begin; ptr < ptr_end; ++ptr) {
		if (ptr[0] != '-' || ptr[1] != '-' ||
		    strncmp(&ptr[2], pmime_parent->boundary_string,
		    pmime_parent->boundary_len) != 0)
			continue;
		if (ptr[pmime_parent->boundary_len+2] != '\r' &&
		    ptr[pmime_parent->boundary_len+2] != '\n' &&
		    ptr[pmime_parent->boundary_len+2] != '-')
			continue;
		mime_uq = MIME::create();
		pmime = mime_uq.get();
		if (NULL == pmime) {
			mlog(LV_ERR, "mail: MIME pool exhausted (too many parts in mail)");
			return false;
		}
		if (!pmime->load_from_str(pmime_parent, ptr_last, ptr - ptr_last))
			return false;
		if (pmime->mime_type == mime_type::none) {
			mlog(LV_DEBUG, "mail: fatal error in %s", __PRETTY_FUNCTION__);
			return false;
		}
		if (pmime_last == nullptr)
			pmail->tree.add_child(&pmime_parent->stree,
				std::move(mime_uq), SIMPLE_TREE_ADD_LAST);
		else
			pmail->tree.insert_sibling(&pmime_last->stree,
				std::move(mime_uq), SIMPLE_TREE_INSERT_AFTER);
		pmime_last = pmime;
		if (pmime->mime_type == mime_type::multiple) {
			auto fss = pmime->first_boundary == nullptr ? nullptr : &pmime->first_boundary[pmime->boundary_len+2];
			auto nl_len = fss == nullptr ? 0 : newline_size(fss, pmime->last_boundary - fss);
			if (!mail_retrieve_to_mime(pmail, pmime,
			    &fss[nl_len], pmime->last_boundary))
				return false;
		}
		if (ptr[2+pmime_parent->boundary_len] == '-' &&
		    ptr[3+pmime_parent->boundary_len] == '-')
			return true;
		ptr += pmime_parent->boundary_len + 2;
		auto nl_len = newline_size(ptr, 2);
		ptr += nl_len;
		ptr_last = ptr;
	}
	for (ptr = ptr_last; ptr < ptr_end; ++ptr)
		if (*ptr != '\t' && *ptr != ' ' && *ptr != '\r' && *ptr != '\n')
			break;
	if (ptr >= ptr_end)
		return true;
	/* some illegal multiple mimes haven't --boundary string-- */
	mime_uq = MIME::create();
	pmime = mime_uq.get();
	if (NULL == pmime) {
		mlog(LV_ERR, "mail: MIME pool exhausted (too many parts in mail)");
		return false;
	}
	if (!pmime->load_from_str(pmime_parent, ptr_last, ptr_end - ptr_last))
		return false;
	if (pmime->mime_type == mime_type::none) {
		mlog(LV_DEBUG, "mail: fatal error in %s", __PRETTY_FUNCTION__);
		return false;
	}
	if (pmime_last == nullptr)
		pmail->tree.add_child(&pmime_parent->stree,
			std::move(mime_uq), SIMPLE_TREE_ADD_LAST);
	else
		pmail->tree.insert_sibling(&pmime_last->stree,
			std::move(mime_uq), SIMPLE_TREE_INSERT_AFTER);
	if (pmime->mime_type != mime_type::multiple)
		return true;
	auto fss = &pmime->first_boundary[pmime->boundary_len+2];
	auto nl_len = newline_size(fss, pmime->last_boundary - fss);
	return mail_retrieve_to_mime(pmail, pmime, &fss[nl_len], pmime->last_boundary);
}

/*
 *	serialize the mail object into stream
 *	@param
 *		pmail [in]			indicate the mail object
 *		pstream [in]		stream for retrieving mail object
 *	@return
 *		TRUE				OK
 *		FALSE				fail
 */
bool MAIL::serialize(STREAM *pstream) const
{
	auto pmail = this;
#ifdef _DEBUG_UMTA
	if (pstream == nullptr)
		return false;
#endif
	auto pnode = pmail->tree.get_root();
	if (pnode == nullptr)
		return false;
	return static_cast<const MIME *>(pnode->pdata)->serialize(pstream);
}

errno_t MAIL::to_fd(int fd) const
{
	STREAM st;
	if (!serialize(&st))
		return ENOMEM;
	void *data;
	unsigned int size = STREAM_BLOCK_SIZE;
	while ((data = st.get_read_buf(&size)) != nullptr) {
		auto wrret = HXio_fullwrite(fd, data, size);
		if (wrret < 0)
			return errno;
		if (static_cast<size_t>(wrret) != size)
			/*
			 * Can't really happen right, either it is fully
			 * written or there is a negative return.
			 */
			return ENOSPC;
		size = STREAM_BLOCK_SIZE;
	}
	return 0;
}

errno_t MAIL::to_str(std::string &out) const try
{
	STREAM st;
	if (!serialize(&st))
		return ENOMEM;
	char *data;
	unsigned int size = STREAM_BLOCK_SIZE;
	while ((data = static_cast<char *>(st.get_read_buf(&size))) != nullptr) {
		out.append(data, size);
		size = STREAM_BLOCK_SIZE;
	}
	return 0;
} catch (const std::bad_alloc &) {
	return ENOMEM;
}

/*
 *	calculate the mail object length in bytes
 *	@param
 *		pmail [in]		indicate the mail object
 *	@return
 *		length of mail in bytes
 */
ssize_t MAIL::get_length() const
{
	auto pmail = this;
	auto pnode = pmail->tree.get_root();
	if (pnode == nullptr)
		return -1;
	auto mime = static_cast<const MIME *>(pnode->pdata);
	return mime != nullptr ? mime->get_length() : -1;
}

MAIL::~MAIL()
{
	clear();
	tree.clear();
}

MAIL &MAIL::operator=(MAIL &&o)
{
	clear();
	tree.clear();
	tree = o.tree;
	o.tree = {};
	buffer = o.buffer;
	o.buffer = nullptr;
	return *this;
}

/*
 *	add mail head into mail
 *	@param
 *		pmail [in]			indicate the mail object
 *	@return
 *		new added mail head mime
 */
MIME *MAIL::add_head()
{
	auto pmail = this;
	if (pmail->tree.get_root() != nullptr)
		return NULL;
	auto mime_uq = MIME::create();
	auto pmime = mime_uq.get();
	if (pmime == nullptr)
		return NULL;
	pmime->clear();
	pmail->tree.set_root(std::move(mime_uq));
	return pmime;
}

MIME *MAIL::get_head()
{
	auto pmail = this;
	auto pnode = pmail->tree.get_root();
	return pnode != nullptr ? static_cast<MIME *>(pnode->pdata) : nullptr;
}

const MIME *MAIL::get_head() const { return deconst(this)->get_head(); }

bool MAIL::get_charset(std::string &charset) const try
{
	auto pmail = this;
	char temp_buff[1024];
	ENCODE_STRING encode_string;
	
#ifdef _DEBUG_UMTA
	if (charset == nullptr) {
		mlog(LV_DEBUG, "NULL pointer in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	charset.clear();
	auto pnode = pmail->tree.get_root();
	if (pnode == nullptr)
		return false;
	auto pmime = static_cast<const MIME *>(pnode->pdata);
	if (pmime->get_field("Subject", temp_buff, 512)) {
		parse_mime_encode_string(temp_buff, strlen(temp_buff),
			&encode_string);
		if (0 != strcmp(encode_string.charset, "default")) {
			charset = encode_string.charset;
			return true;
		}
	}
	if (pmime->get_field("From", temp_buff, 512)) {
		parse_mime_encode_string(temp_buff, strlen(temp_buff),
			&encode_string);
		if (0 != strcmp(encode_string.charset, "default")) {
			charset = encode_string.charset;
			return true;
		}
	}
	pmail->enum_mime(mail_enum_text_mime_charset, &charset);
	if (!charset.empty())
		return true;
	pmail->enum_mime(mail_enum_html_charset, &charset);
	return !charset.empty();
} catch (const std::bad_alloc &) {
	return false;
}

static void replace_qb(char *s)
{
	for (; *s != '\0'; ++s)
		if (*s == '"' || *s == '\\')
			*s = ' ';
}

/*
 *	get the digest string of mail
 *	@param
 *		poffset [out]       for retrieving mail length
 *	@return
 *	   -1                   fatal error
 *		0					buffer length insufficient
 *		1					digest mail OK
 */
int MAIL::make_digest(size_t *poffset, Json::Value &digest) const try
{
	auto pmail = this;
	char *ptr;
	int priority;
	BOOL b_tags[TAG_NUM];
	char temp_buff[1024];

#ifdef _DEBUG_UMTA
	if (poffset == nullptr) {
		mlog(LV_DEBUG, "NULL pointer in %s", __PRETTY_FUNCTION__);
		return -1;
	}
#endif
	auto pnode = pmail->tree.get_root();
	if (pnode == nullptr)
		return -1;

	digest = Json::objectValue;
	auto pmime = static_cast<const MIME *>(pnode->pdata);
	if (pmime->get_field("Message-ID", temp_buff, 128))
		digest["msgid"] = base64_encode(temp_buff);
	if (pmime->get_field("Date", temp_buff, 128))
		digest["date"] = base64_encode(temp_buff);
	if (pmime->get_field("From", temp_buff, 512))
		digest["from"] = base64_encode(temp_buff);
	if (pmime->get_field("Sender", temp_buff, 512)) {
		auto s = base64_encode(temp_buff);
		if (!s.empty())
			digest["sender"] = std::move(s);
	}
	if (pmime->get_field("Reply-To", temp_buff, 512)) {
		auto s = base64_encode(temp_buff);
		if (!s.empty())
			digest["reply"] = std::move(s);
	}
	if (pmime->get_field("To", temp_buff, 1024))
		digest["to"] = base64_encode(temp_buff);
	if (pmime->get_field("Cc", temp_buff, 1024))
		digest["cc"] = base64_encode(temp_buff);
	if (pmime->get_field("In-Reply-To", temp_buff, 512)) {
		auto s = base64_encode(temp_buff);
		if (!s.empty())
			digest["inreply"] = std::move(s);
	}

	if (!pmime->get_field("X-Priority", temp_buff, 32)) {
		priority = 3;
	} else {
		priority = strtol(temp_buff, nullptr, 0);
		if (priority <= 0 || priority > 5)
			priority = 3;
	}

	if (pmime->get_field("Subject", temp_buff, 512))
		digest["subject"] = base64_encode(temp_buff);
	
	if (!pmime->get_field("Received", temp_buff, 256)) {
		digest["received"] = digest["date"];
	} else {
		ptr = strrchr(temp_buff, ';');
		if (NULL == ptr) {
			digest["received"] = digest["date"];
		} else {
			ptr ++;
			while (*ptr == ' ' || *ptr == '\t')
				ptr ++;
			digest["received"] = base64_encode(ptr);
		}
	}

	std::string email_charset;
	get_charset(email_charset);
	digest["uid"]       = 0;
	digest["recent"]    = 1;
	digest["read"]      = 0;
	digest["replied"]   = 0;
	digest["unsent"]    = 0;
	digest["forwarded"] = 0;
	digest["flag"]      = 0;
	digest["priority"]  = Json::Value::UInt64(priority);
	if (!email_charset.empty() && str_isasciipr(email_charset.c_str())) {
		replace_qb(email_charset.data());
		digest["charset"] = std::move(email_charset);
	}
	if (pmime->get_field("Disposition-Notification-To", temp_buff, 1024))
		digest["notification"] = base64_encode(temp_buff);
	if (pmime->get_field("References", temp_buff, 1024))
		digest["ref"] = base64_encode(temp_buff);

	b_tags[TAG_SIGNED] = FALSE;
	b_tags[TAG_ENCRYPT] = FALSE;
	
	simple_tree_enum_from_node(pmail->tree.get_root(), [&](const tree_node *n, unsigned int) {
		auto m = static_cast<const MIME *>(n->pdata);
		if (strcasecmp(m->content_type, "multipart/signed") == 0)
			b_tags[TAG_SIGNED] = TRUE;
		std::string buf;
		if (m->get_content_param("smime-type", buf))
			b_tags[TAG_ENCRYPT] = TRUE;
	});
	if (b_tags[TAG_SIGNED])
		digest["signed"] = 1;
	if (b_tags[TAG_ENCRYPT])
		digest["encrypt"] = 1;
	*poffset = 0;
	Json::Value dsarray = Json::arrayValue;
	if (pmail->get_head()->make_structure_digest("", poffset, dsarray) < 0)
		return -1;
	digest["structure"] = std::move(dsarray);
	*poffset = 0;
	dsarray = Json::arrayValue;
	if (pmail->get_head()->make_mimes_digest("", poffset, dsarray) < 0)
		return -1;
	digest["mimes"] = std::move(dsarray);
	digest["size"] = Json::Value::UInt64(*poffset);
	return 1;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1131: ENOMEM");
	return -1;
}

static void mail_enum_text_mime_charset(const MIME *pmime, void *param)
{
	auto &cset = *static_cast<std::string *>(param);
	
	if (!cset.empty())
		return; /* already found something earlier */
	if (0 == strncasecmp(pmime->content_type, "text/", 5) &&
	    pmime->get_content_param("charset", cset)) {
		replace_qb(cset.data());
		HX_strrtrim(cset.data());
		HX_strltrim(cset.data());
		cset.resize(strlen(cset.c_str()));
	}
}

static void mail_enum_html_charset(const MIME *pmime, void *param) try
{
	auto &cset = *static_cast<std::string *>(param);
	int i;
	/* read_content won't do partial reads, so this buf is kinda large. yuck. */
	auto buff = std::make_unique<char[]>(128*1024);
	
	if (!cset.empty())
		return; /* already found something earlier */
	if (strcasecmp(pmime->content_type, "text/html") != 0)
		return;
	size_t length = 128 * 1024 - 1;
	if (!pmime->read_content(buff.get(), &length))
		return;
	if (length > 4096)
		length = 4096;
	buff[length] = '\0';
	const char *ptr = strcasestr(buff.get(), "charset=");
	if (ptr == nullptr)
		return;
	ptr += 8;
	if (*ptr == '"' || *ptr == '\'')
		ptr ++;
	auto start = ptr, stop = ptr;
	for (i=0; i<32; i++) {
		if ('"' == ptr[i] || '\'' == ptr[i] || ' ' == ptr[i] ||
			',' == ptr[i] || ';' == ptr[i] || '>' == ptr[i]) {
			break;
		} else {
			++stop;
		}
	}
	cset.assign(start, stop - start);
} catch (const std::bad_alloc &) {
}

/*
 *  add a child mime to pbase_mime
 *  @param
 *      pmail [in]          indicate the mail object
 *      pmime_base [in]     indicate the base mime to be compared with
 *      opt                 MIME_ADD_FIRST
 *                          MIME_ADD_LAST
 *  @return
 *		new created mime
 */
MIME *MAIL::add_child(MIME *pmime_base, int opt)
{
	auto pmail = this;

#ifdef _DEBUG_UMTA
	if (pmime_base == nullptr) {
	        mlog(LV_DEBUG, "NULL pointer in %s", __PRETTY_FUNCTION__);
        return NULL;
    }
#endif
	if (pmime_base->mime_type != mime_type::multiple)
		return NULL;
	auto mime_uq = MIME::create();
	auto pmime = mime_uq.get();
    if (NULL == pmime) {
        return NULL;
    }
	pmime->clear();
	if (!pmail->tree.add_child(&pmime_base->stree, std::move(mime_uq), opt))
        return NULL;
    return pmime;
}

void MAIL::enum_mime(MAIL_MIME_ENUM enum_func, void *param) const
{
	auto pmail = this;
#ifdef _DEBUG_UMTA
	if (enum_func == nullptr) {
	        mlog(LV_DEBUG, "NULL pointer in %s", __PRETTY_FUNCTION__);
        return;
    }
#endif
	simple_tree_enum_from_node(pmail->tree.get_root(), [&](const tree_node *stn, unsigned int) {
		auto m = containerof(stn, const MIME, stree);
		enum_func(m, param);
	});
}

/*
 *	copy a mail object into another one
 *	@param
 *		pmail_src [in]			mail source object
 *		pmail_dst [in, out]		mail destination object
 */
bool MAIL::dup(MAIL *pmail_dst)
{
	auto pmail_src = this;
	unsigned int size;
	void *ptr;
	
#ifdef _DEBUG_UMTA
	if (pmail_dst == nullptr) {
		mlog(LV_DEBUG, "NULL pointer in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	pmail_dst->clear();
	auto mail_len = get_length();
	if (mail_len < 0)
		return false;
	STREAM tmp_stream;
	if (!pmail_src->serialize(&tmp_stream))
		return false;
	auto pbuff = me_alloc<char>(strange_roundup(mail_len - 1, 64 * 1024));
	if (NULL == pbuff) {
		mlog(LV_DEBUG, "Failed to allocate memory in %s", __PRETTY_FUNCTION__);
		return false;
	}
			
	size_t offset = 0;
	size = STREAM_BLOCK_SIZE;
	while ((ptr = tmp_stream.get_read_buf(&size)) != nullptr) {
		memcpy(pbuff + offset, ptr, size);
		offset += size;
		size = STREAM_BLOCK_SIZE;
	}
	tmp_stream.clear();
	if (!pmail_dst->load_from_str(pbuff, offset)) {
		free(pbuff);
		return false;
	} else {
		pmail_dst->buffer = pbuff;
		return true;
	}
}
