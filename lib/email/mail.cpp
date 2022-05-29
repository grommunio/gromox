// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdio>
#include <cstring>
#include <memory>
#include <utility>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <gromox/fileio.h>
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

static BOOL mail_retrieve_to_mime(MAIL *pmail, MIME* pmime_parent,
	char *ptr_begin, char *ptr_end);
static void mail_enum_delete(SIMPLE_TREE_NODE *pnode);
static BOOL mail_check_ascii_printable(const char *astring);
static void mail_enum_text_mime_charset(MIME *, void *);
static void mail_enum_html_charset(MIME *, void *);

MAIL::MAIL(std::shared_ptr<MIME_POOL> p) : pmime_pool(std::move(p))
{
	simple_tree_init(&tree);
}

void MAIL::clear()
{
	auto pmail = this;
	auto pnode = pmail->tree.get_root();
	if (NULL != pnode) {
		pmail->tree.destroy_node(pnode, mail_enum_delete);
	}
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
BOOL MAIL::retrieve(char *in_buff, size_t length)
{
	auto pmail = this;

#ifdef _DEBUG_UMTA
	if (in_buff == nullptr) {
		debug_info("[mail]: NULL pointer in mail_retrieve");
		return FALSE;
	}
#endif
	clear();
	auto pmime = pmail->pmime_pool->get_mime();
	if (NULL == pmime) {
		debug_info("[mail]: fail to get mime from pool");
		return FALSE;
	}
	if (!pmime->retrieve(nullptr, in_buff, length)) {
		pmail->pmime_pool->put_mime(pmime);
		return FALSE;
	}

	if (pmime->mime_type != mime_type::single &&
	    pmime->mime_type != mime_type::multiple) {
		debug_info("[mail]: fatal error in mime_retrieve");
		pmail->pmime_pool->put_mime(pmime);
		return FALSE;
	}
	pmail->tree.set_root(&pmime->node);
	if (pmime->mime_type != mime_type::multiple ||
	    mail_retrieve_to_mime(pmail, pmime, pmime->first_boundary +
	    pmime->boundary_len + 4, pmime->last_boundary))
		return TRUE;

	pmail->clear();
	/* retrieve as single mail object */
	pmime = pmail->pmime_pool->get_mime();
	if (NULL == pmime) {
		debug_info("[mail]: fail to get mime from pool");
		return FALSE;
	}
	if (!pmime->retrieve(nullptr, in_buff, length)) {
		pmail->pmime_pool->put_mime(pmime);
		return FALSE;
	}
	pmime->mime_type = mime_type::single;
	pmail->tree.set_root(&pmime->node);
	return TRUE;
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
static BOOL mail_retrieve_to_mime(MAIL *pmail, MIME *pmime_parent,
	char *ptr_begin, char *ptr_end)
{
	MIME *pmime, *pmime_last;
	char *ptr, *ptr_last;

	ptr = ptr_begin;
	ptr_last = ptr_begin;
	pmime_last = NULL;
	while (ptr < ptr_end) {
		if (ptr[0] == '-' && ptr[1] == '-' &&
			strncmp(ptr + 2, pmime_parent->boundary_string, 
			pmime_parent->boundary_len) == 0 &&
			('\r' == ptr[2 + pmime_parent->boundary_len] ||
			'-' == ptr[2 + pmime_parent->boundary_len])) {
			pmime = pmail->pmime_pool->get_mime();
			if (NULL == pmime) {
				debug_info("[mail]: fail to get mime from pool");
				return FALSE;
			}
			if (!pmime->retrieve(pmime_parent, ptr_last, ptr - ptr_last)) {
				pmail->pmime_pool->put_mime(pmime);
				return FALSE;
			}
			if (pmime->mime_type != mime_type::single &&
			    pmime->mime_type != mime_type::multiple) {
				debug_info("[mail]: fatal error in mime_retrieve_to_mime");
				pmail->pmime_pool->put_mime(pmime);
				return FALSE;
			}
			if (NULL == pmime_last) {
				pmail->tree.add_child(&pmime_parent->node,
					&pmime->node,SIMPLE_TREE_ADD_LAST);
            } else {
				pmail->tree.insert_sibling(&pmime_last->node,
					&pmime->node, SIMPLE_TREE_INSERT_AFTER);
            }
			pmime_last = pmime;
			if (pmime->mime_type == mime_type::multiple &&
			    !mail_retrieve_to_mime(pmail, pmime,
			    pmime->first_boundary + pmime->boundary_len + 4,
			    pmime->last_boundary))
				return FALSE;
			if ('-' == ptr[2 + pmime_parent->boundary_len] &&
				'-' == ptr[3 + pmime_parent->boundary_len]) {
				return TRUE;
			}
			ptr += pmime_parent->boundary_len + 4;
			ptr_last = ptr;
		}
		ptr ++;
	}
	for (ptr=ptr_last; ptr<ptr_end; ptr++) {
		if ('\t' != *ptr && ' ' != *ptr && '\r' != *ptr && '\n' != *ptr) {
			break;
		}
	}
	if (ptr >= ptr_end) {
		return TRUE;
	}
	/* some illegal multiple mimes haven't --boundary string-- */
	pmime = pmail->pmime_pool->get_mime();
	if (NULL == pmime) {
		debug_info("[mail]: fail to get mime from pool");
		return FALSE;
	}
	if (!pmime->retrieve(pmime_parent, ptr_last, ptr_end - ptr_last)) {
		pmail->pmime_pool->put_mime(pmime);
		return FALSE;
	}
	if (pmime->mime_type != mime_type::single &&
	    pmime->mime_type != mime_type::multiple) {
		debug_info("[mail]: fatal error in mime_retrieve_to_mime");
		pmail->pmime_pool->put_mime(pmime);
		return FALSE;
	}
	if (NULL == pmime_last) {
		pmail->tree.add_child(&pmime_parent->node,
			&pmime->node,SIMPLE_TREE_ADD_LAST);
    } else {
		pmail->tree.insert_sibling(&pmime_last->node,
			&pmime->node, SIMPLE_TREE_INSERT_AFTER);
	}
	if (pmime->mime_type == mime_type::multiple &&
	    !mail_retrieve_to_mime(pmail, pmime,
	    pmime->first_boundary + pmime->boundary_len + 4,
	    pmime->last_boundary))
		return FALSE;
	return TRUE;
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
BOOL MAIL::serialize(STREAM *pstream)
{
	auto pmail = this;
#ifdef _DEBUG_UMTA
	if (pstream == nullptr)
		return FALSE;
#endif
	auto pnode = pmail->tree.get_root();
	return pnode != nullptr ? static_cast<MIME *>(pnode->pdata)->serialize(pstream) : false;
}

/*
 *	serialize the mail object into file
 *	@param
 *		pmail [in]		indicate the mail object
 *		fd				file descriptor
 *	@return
 *		TRUE			OK
 *		FALSE			fail
 */
BOOL MAIL::to_file(int fd)
{
	auto pmail = this;
	auto pnode = pmail->tree.get_root();
	return pnode != nullptr ? static_cast<MIME *>(pnode->pdata)->to_file(fd) : false;
}

/*
 *	serialize the mail object into ssl
 *	@param
 *		pmail [in]		indicate the mail object
 *		ssl [in]		SSL object
 *	@return
 *		TRUE			OK
 *		FALSE			fail
 */
BOOL MAIL::to_ssl(SSL *ssl)
{
	auto pmail = this;
#ifdef _DEBUG_UMTA
	if (ssl == nullptr)
		return FALSE;
#endif
	auto pnode = pmail->tree.get_root();
	return pnode != nullptr ? static_cast<MIME *>(pnode->pdata)->to_tls(ssl) : false;
}

/*
 *	check if dot-stuffing in mail
 *	@param
 *		pmail [in]		indicate the mail object
 *	@return
 *		TRUE			dot-stuffing in mail
 *		FALSE			no dot-stuffing in mail
 */
BOOL MAIL::check_dot()
{
	auto pmail = this;
	auto pnode = pmail->tree.get_root();
	return pnode != nullptr ? static_cast<MIME *>(pnode->pdata)->check_dot() : false;
}

/*
 *	calculate the mail object length in bytes
 *	@param
 *		pmail [in]		indicate the mail object
 *	@return
 *		length of mail in bytes
 */
ssize_t MAIL::get_length()
{
	auto pmail = this;
	auto pnode = pmail->tree.get_root();
	return pnode != nullptr ? static_cast<MIME *>(pnode->pdata)->get_length() : -1;
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
	if (NULL == pmime) {
		return NULL;
	}
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

static BOOL mail_check_ascii_printable(const char *astring)
{
	int i, len;
	
	len = strlen(astring);
	
	for (i=0; i<len; i++) {
		if (astring[i] < 0x20 || astring[i] > 0x7E) {
			return FALSE;
		}
	}
	return TRUE;
}

BOOL MAIL::get_charset(char *charset)
{
	auto pmail = this;
	MIME *pmime;
	char temp_buff[1024];
	ENCODE_STRING encode_string;
	
#ifdef _DEBUG_UMTA
	if (charset == nullptr) {
		debug_info("[mail]: NULL pointer in mail_get_charset");
		return FALSE;
	}
#endif
	charset[0] = '\0';
	auto pnode = pmail->tree.get_root();
	if (NULL == pnode) {
		return FALSE;
	}
	pmime = (MIME*)pnode->pdata;
	if (pmime->get_field("Subject", temp_buff, 512)) {
		parse_mime_encode_string(temp_buff, strlen(temp_buff),
			&encode_string);
		if (0 != strcmp(encode_string.charset, "default")) {
			strcpy(charset, encode_string.charset);
			return TRUE;
		}
	}
	if (pmime->get_field("From", temp_buff, 512)) {
		parse_mime_encode_string(temp_buff, strlen(temp_buff),
			&encode_string);
		if (0 != strcmp(encode_string.charset, "default")) {
			strcpy(charset, encode_string.charset);
			return TRUE;
		}
	}
	pmail->enum_mime(mail_enum_text_mime_charset, charset);
	if ('\0' != charset[0]) {
		return TRUE;
	}
	pmail->enum_mime(mail_enum_html_charset, charset);
	if ('\0' != charset[0]) {
		return TRUE;
	}
	return FALSE;
}

/*
 *	get the digest string of mail
 *	@param
 *		pmail [in]			indicate the mail object
 *		poffset [out]       for retrieving mail length
 *		pbuff [out]			for retrieving the digest
 *		length              maximum length of buffer
 *	@return
 *	   -1                   fatal error
 *		0					buffer length insufficient
 *		1					digest mail OK
 */
int MAIL::get_digest(size_t *poffset, char *pbuff, int length)
{
	auto pmail = this;
	char *ptr;
	MIME *pmime;
	int priority;
	size_t count;
	ssize_t gmd;
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
	if (poffset == nullptr || pbuff == nullptr) {
		debug_info("[mail]: NULL pointer in mail_get_digest");
		return -1;
	}
#endif


	if (length < 128) {
		return -1;
	}
	auto pnode = pmail->tree.get_root();
	if (NULL == pnode) {
		return -1;
	}

	pmime = (MIME*)pnode->pdata;
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
		if (priority <= 0 || priority > 5) {
			priority = 3;
		}
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
			while (' ' == *ptr || '\t' == *ptr) {
				ptr ++;
			}
			encode64(ptr, strlen(ptr), mime_received, 256, NULL);
		}
	}
	
	if (!get_charset(email_charset))
		email_charset[0] = '\0';
	ssize_t buff_len = gx_snprintf(pbuff, length, "\"uid\":0,\"recent\":1,"
				"\"read\":0,\"replied\":0,\"unsent\":0,\"forwarded\":0,"
				"\"flag\":0,\"priority\":%d,\"msgid\":\"%s\",\"from\":"
				"\"%s\",\"to\":\"%s\",\"cc\":\"%s\",\"subject\":\"%s\","
				"\"received\":\"%s\",\"date\":\"%s\"", priority,
				mime_msgid, mime_from, mime_to, mime_cc,
				mime_subject, mime_received, mime_date);
	if (buff_len >= length - 1) {
		goto PARSE_FAILURE;
	}
	
	if (email_charset[0] != '\0' && mail_check_ascii_printable(email_charset)) {
		auto tmp_len = strlen(email_charset);
		for (size_t i = 0; i < tmp_len; ++i) {
			if ('"' == email_charset[i] || '\\' == email_charset[i]) {
				email_charset[i] = ' ';
			}
		}
		buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
					",\"charset\":\"%s\"", email_charset);
		if (buff_len >= length - 1) {
			goto PARSE_FAILURE;
		}
	}

	if ('\0' != mime_sender[0]) {
		buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
					",\"sender\":\"%s\"", mime_sender);
		if (buff_len >= length - 1) {
			goto PARSE_FAILURE;
		}
	}

	if ('\0' != mime_reply_to[0]) {
		buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
					",\"reply\":\"%s\"", mime_reply_to);
		if (buff_len >= length - 1) {
			goto PARSE_FAILURE;
		}
	}

	if ('\0' != mime_in_reply_to[0]) {
		buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
					",\"inreply\":\"%s\"", mime_in_reply_to);
		if (buff_len >= length - 1) {
			goto PARSE_FAILURE;
		}
	}

	if (pmime->get_field("Disposition-Notification-To", temp_buff, 1024)) {
		encode64(temp_buff, strlen(temp_buff), mime_notification, 1024, NULL);
		buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
					",\"notification\":\"%s\"", mime_notification);

		if (buff_len >= length - 1) {
			goto PARSE_FAILURE;
		}
	}

	if (pmime->get_field("References", temp_buff, 1024)) {
		encode64(temp_buff, strlen(temp_buff), mime_reference, 2048, NULL);
		buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
					",\"ref\":\"%s\"", mime_reference);
	}

	b_tags[TAG_SIGNED] = FALSE;
	b_tags[TAG_ENCRYPT] = FALSE;
	
	simple_tree_enum_from_node(pmail->tree.get_root(), [&](SIMPLE_TREE_NODE *n) {
		char buf[1024];
		auto m = static_cast<MIME *>(n->pdata);
		if (strcasecmp(m->content_type, "multipart/signed") == 0)
			b_tags[TAG_SIGNED] = TRUE;
		if (m->get_content_param("smime-type", buf, arsizeof(buf)))
			b_tags[TAG_ENCRYPT] = TRUE;
	});
	if (b_tags[TAG_SIGNED]) {
		memcpy(pbuff + buff_len, ",\"signed\":1", 11);
		buff_len += 11;
	}
	if (b_tags[TAG_ENCRYPT]) {
		memcpy(pbuff + buff_len, ",\"encrypt\":1", 12);
		buff_len += 12;
	}

	count = 0;
	memcpy(pbuff + buff_len, ",\"structure\":[", 14);
	buff_len += 14;
	*poffset = 0;
	gmd = pmail->get_head()->get_structure_digest("",
	      poffset, &count, pbuff + buff_len, length - buff_len);
	if (gmd < 0 || buff_len + gmd > length - 2) {
		goto PARSE_FAILURE;
	} else {
		buff_len += gmd;
		pbuff[buff_len] = ']';
		buff_len ++;
	}
	
	count = 0;
	memcpy(pbuff + buff_len, ",\"mimes\":[", 10);
	buff_len += 10;
	*poffset = 0;
	gmd = pmail->get_head()->get_mimes_digest("", poffset, &count,
	      pbuff + buff_len, length - buff_len);
	if (gmd < 0 || buff_len + gmd > length - 20) {
		goto PARSE_FAILURE;
	} else {
		buff_len += gmd;
		sprintf(pbuff + buff_len, "],\"size\":%zu", *poffset);
		return 1;
	}
	
 PARSE_FAILURE:
	auto mgl = pmail->get_length();
	if (mgl < 0)
		return -1;
	snprintf(pbuff, length, "\"recent\":1,\"read\":0,\"replied\":0,"
		"\"unsent\":0,\"forwarded\":0,\"flag\":0,\"size\":%zd", mgl);
	*poffset = mgl;
	return 0;
}

static void mail_enum_text_mime_charset(MIME *pmime, void *param)
{
	auto email_charset = static_cast<char *>(param);
	int i, tmp_len;
	
	if ('\0' != email_charset[0]) {
		return;
	}
	if (0 == strncasecmp(pmime->content_type, "text/", 5) &&
	    pmime->get_content_param("charset", email_charset, 32)) {
		tmp_len = strlen(email_charset);
		for (i=0; i<tmp_len; i++) {
			if ('"' == email_charset[i] || '\'' == email_charset[i] ||
				'\\' == email_charset[i]) {
				email_charset[i] = ' ';
			}
		}
		HX_strrtrim(email_charset);
		HX_strltrim(email_charset);
	}
}

static void mail_enum_html_charset(MIME *pmime, void *param)
{
	auto email_charset = static_cast<char *>(param);
	int i;
	char *ptr;
	size_t length;
	char buff[128*1024];
	
	if ('\0' != email_charset[0]) {
		return;
	}
	if (0 != strcasecmp(pmime->content_type, "text/html")) {
		return;
	}
	length = 128*1024;
	if (pmime->read_content(buff, &length)) {
		if (length > 4096) {
			length = 4096;
		}
		ptr = search_string(buff, "charset=", length);
		if (NULL != ptr) {
			ptr += 8;
			if ('"' == *ptr || '\'' == *ptr) {
				ptr ++;
			}
			for (i=0; i<32; i++) {
				if ('"' == ptr[i] || '\'' == ptr[i] || ' ' == ptr[i] ||
					',' == ptr[i] || ';' == ptr[i] || '>' == ptr[i]) {
					email_charset[i] = '\0';
					break;
				} else {
					email_charset[i] = ptr[i];
				}
			}
			if (32 == i) {
				email_charset[0] = '\0';
			}
		}
	}
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
        debug_info("[mail]: NULL pointer in mail_add_child");
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

/*
 *  enumerating the mime in the mail tree
 *  @param
 *      pmail [in]      indicate the mail object
 *      enum_func       callback function
 *		param [in]		parameter pointer for enum_func
 */
void MAIL::enum_mime(MAIL_MIME_ENUM enum_func, void *param)
{
	auto pmail = this;
#ifdef _DEBUG_UMTA
	if (enum_func == nullptr) {
        debug_info("[mail]: NULL pointer in mail_enum_mime");
        return;
    }
#endif
	simple_tree_enum_from_node(pmail->tree.get_root(), [&](SIMPLE_TREE_NODE *stn) {
		auto m = containerof(stn, MIME, node);
		enum_func(m, param);
	});
}

static void mail_enum_delete(SIMPLE_TREE_NODE *pnode)
{
#ifdef _DEBUG_UMTA
	if (NULL == pnode) {
		debug_info("[mail]: NULL pointer in mail_enum_delete");
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
BOOL MAIL::dup(MAIL *pmail_dst)
{
	auto pmail_src = this;
	unsigned int size;
	void *ptr;
	
#ifdef _DEBUG_UMTA
	if (pmail_dst == nullptr) {
		debug_info("[mail]: NULL pointer in mail_dup");
        return FALSE;
	}
#endif
	pmail_dst->clear();
	auto mail_len = get_length();
	if (mail_len < 0)
		return false;
	alloc_limiter<stream_block> pallocator(mail_len / STREAM_BLOCK_SIZE + 1);
	STREAM tmp_stream(&pallocator);
	if (!pmail_src->serialize(&tmp_stream)) {
		return FALSE;
	}
	auto pbuff = me_alloc<char>(strange_roundup(mail_len - 1, 64 * 1024));
	if (NULL == pbuff) {
		debug_info("[mail]: Failed to allocate memory in mail_dup");
		return FALSE;
	}
			
	size_t offset = 0;
	size = STREAM_BLOCK_SIZE;
	while ((ptr = tmp_stream.get_read_buf(&size)) != nullptr) {
		memcpy(pbuff + offset, ptr, size);
		offset += size;
		size = STREAM_BLOCK_SIZE;
	}
	tmp_stream.clear();
	if (!pmail_dst->retrieve(pbuff, offset)) {
		free(pbuff);
		return FALSE;
	} else {
		pmail_dst->buffer = pbuff;
		return TRUE;
	}
}

/*
 *	trim dot-stuffing mail object into a clean object
 *	@param
 *		pmail_src [in]			mail source object
 *		pmail_dst [in, out]		mail destination object
 */
BOOL MAIL::transfer_dot(MAIL *pmail_dst)
{
	auto pmail_src = this;
	unsigned int size;
	char *pbuff;
	
#ifdef _DEBUG_UMTA
	if (pmail_dst == nullptr) {
		debug_info("[mail]: NULL pointer in mail_dup");
        return FALSE;
	}
#endif
	pmail_dst->clear();
	auto mail_len = get_length();
	if (mail_len < 0)
		return false;
	alloc_limiter<stream_block> pallocator(mail_len / STREAM_BLOCK_SIZE + 1);
	STREAM tmp_stream(&pallocator);
	if (!pmail_src->serialize(&tmp_stream)) {
		return FALSE;
	}
	pbuff = me_alloc<char>(((mail_len - 1) / (64 * 1024) + 1) * 64 * 1024);
	if (NULL == pbuff) {
		debug_info("[mail]: Failed to allocate memory in mail_dup");
		return FALSE;
	}
	
	size_t offset = 0;
	size = STREAM_BLOCK_SIZE;
	while (tmp_stream.copyline(pbuff + offset, &size) != STREAM_COPY_END) {
		pbuff[offset + size] = '\r';
		size ++;
		pbuff[offset + size] = '\n';
		size ++;
		if ('.' == pbuff[offset] && '.' == pbuff[offset + 1]) {
			size --;
			memmove(pbuff + offset, pbuff + offset + 1, size);
		}
		offset += size;
		size = STREAM_BLOCK_SIZE;
	}
	
	tmp_stream.clear();
	if (!pmail_dst->retrieve(pbuff,  offset)) {
		free(pbuff);
		return FALSE;
	} else {
		pmail_dst->buffer = pbuff;
		return TRUE;
	}
}

