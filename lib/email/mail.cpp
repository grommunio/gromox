// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <memory>
#include <utility>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <gromox/fileio.h>
#include <gromox/json.hpp>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mime_pool.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>

using namespace gromox;

enum {
	TAG_SIGNED,
	TAG_ENCRYPT,
	TAG_NUM
};

static bool mail_retrieve_to_mime(MAIL *, MIME *parent, char *begin, char *end);
static void mail_enum_delete(SIMPLE_TREE_NODE *pnode);
static bool mail_is_asciipr(const char *astring);
static void mail_enum_text_mime_charset(const MIME *, void *);
static void mail_enum_html_charset(const MIME *, void *);

MAIL::MAIL(std::shared_ptr<MIME_POOL> p) : pmime_pool(std::move(p))
{}

void MAIL::clear()
{
	auto pmail = this;
	auto pnode = pmail->tree.get_root();
	if (pnode != nullptr)
		pmail->tree.destroy_node(pnode, mail_enum_delete);
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
bool MAIL::load_from_str_move(char *in_buff, size_t length)
{
	auto pmail = this;

#ifdef _DEBUG_UMTA
	if (in_buff == nullptr) {
		mlog(LV_DEBUG, "NULL pointer in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	clear();
	auto pmime = pmail->pmime_pool->get_mime();
	if (NULL == pmime) {
		mlog(LV_ERR, "mail: MIME pool exhausted (too many parts in mail)");
		return false;
	}
	if (!pmime->load_from_str_move(nullptr, in_buff, length)) {
		pmail->pmime_pool->put_mime(pmime);
		return false;
	}

	if (pmime->mime_type == mime_type::none) {
		mlog(LV_DEBUG, "mail: fatal error in %s", __PRETTY_FUNCTION__);
		pmail->pmime_pool->put_mime(pmime);
		return false;
	}
	pmail->tree.set_root(&pmime->node);
	if (pmime->mime_type != mime_type::multiple)
		return true;
	auto fss = &pmime->first_boundary[pmime->boundary_len+2];
	auto nl_len = newline_size(fss, pmime->last_boundary - fss);
	if (mail_retrieve_to_mime(pmail, pmime, &fss[nl_len], pmime->last_boundary))
		return true;

	pmail->clear();
	/* retrieve as single mail object */
	pmime = pmail->pmime_pool->get_mime();
	if (NULL == pmime) {
		mlog(LV_ERR, "mail: MIME pool exhausted (too many parts in mail)");
		return false;
	}
	if (!pmime->load_from_str_move(nullptr, in_buff, length)) {
		pmail->pmime_pool->put_mime(pmime);
		return false;
	}
	pmime->mime_type = mime_type::single;
	pmail->tree.set_root(&pmime->node);
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
	char *ptr_begin, char *ptr_end)
{
	MIME *pmime, *pmime_last;
	char *ptr, *ptr_last;

	ptr_last = ptr_begin;
	pmime_last = NULL;
	for (ptr = ptr_begin; ptr < ptr_end; ++ptr) {
		if (ptr[0] != '-' || ptr[1] != '-' ||
		    strncmp(&ptr[2], pmime_parent->boundary_string,
		    pmime_parent->boundary_len) != 0)
			continue;
		if (ptr[pmime_parent->boundary_len+2] != '\r' &&
		    ptr[pmime_parent->boundary_len+2] != '\n' &&
		    ptr[pmime_parent->boundary_len+2] != '-')
			continue;
		pmime = pmail->pmime_pool->get_mime();
		if (NULL == pmime) {
			mlog(LV_ERR, "mail: MIME pool exhausted (too many parts in mail)");
			return false;
		}
		if (!pmime->load_from_str_move(pmime_parent, ptr_last, ptr - ptr_last)) {
			pmail->pmime_pool->put_mime(pmime);
			return false;
		}
		if (pmime->mime_type == mime_type::none) {
			mlog(LV_DEBUG, "mail: fatal error in %s", __PRETTY_FUNCTION__);
			pmail->pmime_pool->put_mime(pmime);
			return false;
		}
		if (pmime_last == nullptr)
			pmail->tree.add_child(&pmime_parent->node,
				&pmime->node, SIMPLE_TREE_ADD_LAST);
		else
			pmail->tree.insert_sibling(&pmime_last->node,
				&pmime->node, SIMPLE_TREE_INSERT_AFTER);
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
	pmime = pmail->pmime_pool->get_mime();
	if (NULL == pmime) {
		mlog(LV_ERR, "mail: MIME pool exhausted (too many parts in mail)");
		return false;
	}
	if (!pmime->load_from_str_move(pmime_parent, ptr_last, ptr_end - ptr_last)) {
		pmail->pmime_pool->put_mime(pmime);
		return false;
	}
	if (pmime->mime_type == mime_type::none) {
		mlog(LV_DEBUG, "mail: fatal error in %s", __PRETTY_FUNCTION__);
		pmail->pmime_pool->put_mime(pmime);
		return false;
	}
	if (pmime_last == nullptr)
		pmail->tree.add_child(&pmime_parent->node,
			&pmime->node,SIMPLE_TREE_ADD_LAST);
	else
		pmail->tree.insert_sibling(&pmime_last->node,
			&pmime->node, SIMPLE_TREE_INSERT_AFTER);
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

bool MAIL::emit(MIME::write_func xw, void *fd) const
{
	auto nd = tree.get_root();
	if (nd == nullptr)
		return false;
	return static_cast<const MIME *>(nd->pdata)->emit(xw, fd);
}

bool MAIL::to_file(int fd) const
{
	auto pmail = this;
	auto pnode = pmail->tree.get_root();
	if (pnode == nullptr)
		return false;
	auto f = +[](void *obj, const void *buf, size_t z) {
	         	return ::write(reinterpret_cast<intptr_t>(obj), buf, z);
	         };
	return static_cast<const MIME *>(pnode->pdata)->emit(f,
	       reinterpret_cast<void *>(static_cast<intptr_t>(fd)));
}

bool MAIL::to_tls(SSL *ssl) const
{
	auto pmail = this;
#ifdef _DEBUG_UMTA
	if (ssl == nullptr)
		return false;
#endif
	auto pnode = pmail->tree.get_root();
	if (pnode == nullptr)
		return false;
	auto f = +[](void *obj, const void *buf, size_t z) -> ssize_t {
	         	return SSL_write(static_cast<SSL *>(obj), buf, z);
	         };
	return static_cast<const MIME *>(pnode->pdata)->emit(f, ssl);
}

/*
 *	check if dot-stuffing in mail
 *	@param
 *		pmail [in]		indicate the mail object
 *	@return
 *		TRUE			dot-stuffing in mail
 *		FALSE			no dot-stuffing in mail
 */
bool MAIL::check_dot() const
{
	auto pmail = this;
	auto pnode = pmail->tree.get_root();
	if (pnode == nullptr)
		return false;
	return static_cast<const MIME *>(pnode->pdata)->check_dot();
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
	pmime_pool = o.pmime_pool;
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
	auto pmime = pmail->pmime_pool->get_mime();
	if (pmime == nullptr)
		return NULL;
	pmime->clear();
	pmail->tree.set_root(&pmime->node);
	return pmime;
}

MIME *MAIL::get_head()
{
	auto pmail = this;
	auto pnode = pmail->tree.get_root();
	return pnode != nullptr ? static_cast<MIME *>(pnode->pdata) : nullptr;
}

const MIME *MAIL::get_head() const { return deconst(this)->get_head(); }

static bool mail_is_asciipr(const char *s)
{
	return std::all_of(s, s + strlen(s),
	       [](unsigned char c) { return isascii(c) && isprint(c); });
}

bool MAIL::get_charset(char *charset) const
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
	charset[0] = '\0';
	auto pnode = pmail->tree.get_root();
	if (pnode == nullptr)
		return false;
	auto pmime = static_cast<const MIME *>(pnode->pdata);
	if (pmime->get_field("Subject", temp_buff, 512)) {
		parse_mime_encode_string(temp_buff, strlen(temp_buff),
			&encode_string);
		if (0 != strcmp(encode_string.charset, "default")) {
			strcpy(charset, encode_string.charset);
			return true;
		}
	}
	if (pmime->get_field("From", temp_buff, 512)) {
		parse_mime_encode_string(temp_buff, strlen(temp_buff),
			&encode_string);
		if (0 != strcmp(encode_string.charset, "default")) {
			strcpy(charset, encode_string.charset);
			return true;
		}
	}
	pmail->enum_mime(mail_enum_text_mime_charset, charset);
	if (*charset != '\0')
		return true;
	pmail->enum_mime(mail_enum_html_charset, charset);
	return *charset != '\0';
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
int MAIL::get_digest(size_t *poffset, Json::Value &digest) const try
{
	auto pmail = this;
	char *ptr;
	int priority;
	BOOL b_tags[TAG_NUM];
	char temp_buff[1024];
	char email_charset[64];
	char mime_msgid[256];
	char mime_date[256];
	char mime_from[1024];
	char mime_sender[1024];
	char mime_reply_to[1024];
	char mime_to[2048];
	char mime_cc[2048];
	char mime_in_reply_to[1024];
	char mime_priority[32];
	char mime_subject[1024];
	char mime_received[256];
	char mime_reference[2048];
	char mime_notification[1024];

#ifdef _DEBUG_UMTA
	if (poffset == nullptr) {
		mlog(LV_DEBUG, "NULL pointer in %s", __PRETTY_FUNCTION__);
		return -1;
	}
#endif
	auto pnode = pmail->tree.get_root();
	if (pnode == nullptr)
		return -1;

	auto pmime = static_cast<const MIME *>(pnode->pdata);
	if (!pmime->get_field("Message-ID", temp_buff, 128))
		mime_msgid[0] = '\0';
	else
		encode64(temp_buff, strlen(temp_buff), mime_msgid, 256, NULL);

	if (!pmime->get_field("Date", temp_buff, 128))
		mime_date[0] = '\0';
	else
		encode64(temp_buff, strlen(temp_buff), mime_date, 256, NULL);

	if (!pmime->get_field("From", temp_buff, 512))
		mime_from[0] = '\0';
	else
		encode64(temp_buff, strlen(temp_buff), mime_from, 1024, NULL);

	if (!pmime->get_field("Sender", temp_buff, 512))
		mime_sender[0] = '\0';
	else
		encode64(temp_buff, strlen(temp_buff), mime_sender, 1024, NULL);
	
	if (!pmime->get_field("Reply-To", temp_buff, 512))
		mime_reply_to[0] = '\0';
	else
		encode64(temp_buff, strlen(temp_buff), mime_reply_to, 1024, NULL);

	if (!pmime->get_field("To", temp_buff, 1024))
		mime_to[0] = '\0';
	else
		encode64(temp_buff, strlen(temp_buff), mime_to, 2048, NULL);

	if (!pmime->get_field("Cc", temp_buff, 1024))
		mime_cc[0] = '\0';
	else
		encode64(temp_buff, strlen(temp_buff), mime_cc, 2048, NULL);

	if (!pmime->get_field("In-Reply-To", temp_buff, 512))
		mime_in_reply_to[0] = '\0';
	else
		encode64(temp_buff, strlen(temp_buff), mime_in_reply_to, 1024, NULL);

	if (!pmime->get_field("X-Priority", mime_priority, 32)) {
		priority = 3;
	} else {
		priority = strtol(mime_priority, nullptr, 0);
		if (priority <= 0 || priority > 5)
			priority = 3;
	}

	if (!pmime->get_field("Subject", temp_buff, 512))
		mime_subject[0] = '\0';
	else
		encode64(temp_buff, strlen(temp_buff), mime_subject, 1024, NULL);
	
	if (!pmime->get_field("Received", temp_buff, 256)) {
		strcpy(mime_received, mime_date);
	} else {
		ptr = strrchr(temp_buff, ';');
		if (NULL == ptr) {
			strcpy(mime_received, mime_date);
		} else {
			ptr ++;
			while (*ptr == ' ' || *ptr == '\t')
				ptr ++;
			encode64(ptr, strlen(ptr), mime_received, 256, NULL);
		}
	}
	
	if (!get_charset(email_charset))
		email_charset[0] = '\0';
	digest              = Json::objectValue;
	digest["uid"]       = 0;
	digest["recent"]    = 1;
	digest["read"]      = 0;
	digest["replied"]   = 0;
	digest["unsent"]    = 0;
	digest["forwarded"] = 0;
	digest["flag"]      = 0;
	digest["priority"]  = Json::Value::UInt64(priority);
	digest["msgid"]     = mime_msgid;
	digest["from"]      = mime_from;
	digest["to"]        = mime_to;
	digest["cc"]        = mime_cc;
	digest["subject"]   = mime_subject;
	digest["received"]  = mime_received;
	digest["date"]      = mime_date;
	if (email_charset[0] != '\0' && mail_is_asciipr(email_charset)) {
		replace_qb(email_charset);
		digest["charset"] = email_charset;
	}
	if (*mime_sender != '\0')
		digest["sender"] = mime_sender;
	if (*mime_reply_to != '\0')
		digest["reply"] = mime_reply_to;
	if (*mime_in_reply_to != '\0')
		digest["inreply"] = mime_in_reply_to;

	if (pmime->get_field("Disposition-Notification-To", temp_buff, 1024)) {
		encode64(temp_buff, strlen(temp_buff), mime_notification, 1024, NULL);
		digest["notification"] = mime_notification;
	}

	if (pmime->get_field("References", temp_buff, 1024)) {
		encode64(temp_buff, strlen(temp_buff), mime_reference, 2048, NULL);
		digest["ref"] = mime_reference;
	}

	b_tags[TAG_SIGNED] = FALSE;
	b_tags[TAG_ENCRYPT] = FALSE;
	
	simple_tree_enum_from_node(pmail->tree.get_root(), [&](const tree_node *n, unsigned int) {
		char buf[1024];
		auto m = static_cast<const MIME *>(n->pdata);
		if (strcasecmp(m->content_type, "multipart/signed") == 0)
			b_tags[TAG_SIGNED] = TRUE;
		if (m->get_content_param("smime-type", buf, std::size(buf)))
			b_tags[TAG_ENCRYPT] = TRUE;
	});
	if (b_tags[TAG_SIGNED])
		digest["signed"] = 1;
	if (b_tags[TAG_ENCRYPT])
		digest["encrypt"] = 1;
	*poffset = 0;
	Json::Value dsarray = Json::arrayValue;
	if (pmail->get_head()->get_structure_digest("", poffset, dsarray) < 0)
		return -1;
	digest["structure"] = std::move(dsarray);
	*poffset = 0;
	dsarray = Json::arrayValue;
	if (pmail->get_head()->get_mimes_digest("", poffset, dsarray) < 0)
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
	auto email_charset = static_cast<char *>(param);
	
	if (*email_charset != '\0')
		return;
	if (0 == strncasecmp(pmime->content_type, "text/", 5) &&
	    pmime->get_content_param("charset", email_charset, 32)) {
		replace_qb(email_charset);
		HX_strrtrim(email_charset);
		HX_strltrim(email_charset);
	}
}

static void mail_enum_html_charset(const MIME *pmime, void *param)
{
	auto email_charset = static_cast<char *>(param);
	int i;
	char *ptr;
	size_t length;
	char buff[128*1024];
	
	if (*email_charset == '\0')
		return;
	if (strcasecmp(pmime->content_type, "text/html") != 0)
		return;
	length = 128*1024;
	if (!pmime->read_content(buff, &length))
		return;
	if (length > 4096)
		length = 4096;
	ptr = search_string(buff, "charset=", length);
	if (ptr == nullptr)
		return;
	ptr += 8;
	if (*ptr == '"' || *ptr == '\'')
		ptr ++;
	for (i=0; i<32; i++) {
		if ('"' == ptr[i] || '\'' == ptr[i] || ' ' == ptr[i] ||
			',' == ptr[i] || ';' == ptr[i] || '>' == ptr[i]) {
			email_charset[i] = '\0';
			break;
		} else {
			email_charset[i] = ptr[i];
		}
	}
	if (i == 32)
		email_charset[0] = '\0';
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
	auto pmime = pmail->pmime_pool->get_mime();
    if (NULL == pmime) {
        return NULL;
    }
	pmime->clear();
	if (!pmail->tree.add_child(&pmime_base->node, &pmime->node, opt)) {
		pmail->pmime_pool->put_mime(pmime);
        return NULL;
    }
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
		auto m = containerof(stn, const MIME, node);
		enum_func(m, param);
	});
}

static void mail_enum_delete(SIMPLE_TREE_NODE *pnode)
{
#ifdef _DEBUG_UMTA
	if (NULL == pnode) {
		mlog(LV_DEBUG, "NULL pointer in %s", __PRETTY_FUNCTION__);
		return;
	}
#endif
	auto pmime = static_cast<MIME *>(pnode->pdata);
	pmime->clear();
	MIME_POOL::put_mime(pmime);
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
	alloc_limiter<stream_block> pallocator(mail_len / STREAM_BLOCK_SIZE + 1,
		"mail::dup");
	STREAM tmp_stream(&pallocator);
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
	if (!pmail_dst->load_from_str_move(pbuff, offset)) {
		free(pbuff);
		return false;
	} else {
		pmail_dst->buffer = pbuff;
		return true;
	}
}

/*
 *	add or remove dot-stuffing; copies into a clean object
 *	@param
 *		pmail_src [in]			mail source object
 *		pmail_dst [in, out]		mail destination object
 */
bool MAIL::transfer_dot(MAIL *pmail_dst, bool add_dot)
{
	auto pmail_src = this;
	unsigned int size;
	char *pbuff;
	
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
	alloc_limiter<stream_block> pallocator(mail_len / STREAM_BLOCK_SIZE + 1,
		"mail_transfer_dot");
	STREAM tmp_stream(&pallocator);
	if (!pmail_src->serialize(&tmp_stream))
		return false;
	pbuff = me_alloc<char>(((mail_len - 1) / (64 * 1024) + 1) * 64 * 1024);
	if (NULL == pbuff) {
		mlog(LV_DEBUG, "Failed to allocate memory in %s", __PRETTY_FUNCTION__);
		return false;
	}
	
	size_t offset = 0;
	size = STREAM_BLOCK_SIZE - 3;
	while (tmp_stream.copyline(pbuff + offset, &size) != STREAM_COPY_END) {
		pbuff[offset + size++] = '\r';
		pbuff[offset + size++] = '\n';
		if (add_dot) {
			if (pbuff[offset] == '.') {
				memmove(&pbuff[offset+1], &pbuff[offset], size);
				++size;
			}
		} else if (pbuff[offset] == '.' && pbuff[offset+1] == '.') {
			size --;
			memmove(pbuff + offset, pbuff + offset + 1, size);
		}
		offset += size;
		size = STREAM_BLOCK_SIZE - 3;
	}
	
	tmp_stream.clear();
	if (!pmail_dst->load_from_str_move(pbuff, offset)) {
		free(pbuff);
		return false;
	} else {
		pmail_dst->buffer = pbuff;
		return true;
	}
}

