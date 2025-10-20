// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020-2025 grommunio GmbH
// This file is part of Gromox.
/*
 * normally, MIME object does'n maintain its own content buffer, it just take
 * the reference of a mail object buffer, mark the begin, end and the content
 * point. if the user uses the MIME::write_content function, the MIME object
 * will then maintain its own buffer.
 */
#include <algorithm>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <unistd.h>
#include <utility>
#include <fmt/core.h>
#include <libHX/io.h>
#include <libHX/string.h>
#include <gromox/fileio.h>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mime.hpp>
#include <gromox/util.hpp>

using namespace gromox;

static bool mime_parse_multiple(MIME *);
static void mime_produce_boundary(MIME *pmime);

bool MAIL::set_header(const char *hdr, const char *val)
{
	auto mail = this;
	auto node = mail->tree.get_root();
	if (node == nullptr)
		return false;
	return static_cast<MIME *>(node->pdata)->set_field(hdr, val);
}

MIME::MIME()
{
	stree.pdata = this;
}

MIME::~MIME()
{
	auto pmime = this;

	if (pmime->mime_type != mime_type::multiple)
		return;
	auto pnode = pmime->stree.get_child();
	while (NULL != pnode) {
		delete static_cast<MIME *>(pnode->pdata);
		pnode = pnode->get_sibling();
	}
}

/*
 *	retrieve a mime buffer into mime object
 *	@param
 *		pmime_parent [in]	parent mime object
 *		pmime [in, out]		mime object
 *		in_buff [in]		buffer that contains a mime
 *		length				length of the buffer
 *	@return
 *		TRUE				OK to parse mime buffer
 *		FALSE				fail to parse mime buffer, there's error inside
 */
bool MIME::load_from_str(MIME *pmime_parent, const char *in_buff, size_t length) try
{
	auto pmime = this;
	size_t current_offset = 0;

#ifdef _DEBUG_UMTA
	if (in_buff == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	
	pmime->clear();
	if (0 == length) {
		/* No content: syntactically same as implied plaintext */
		pmime->head_touched = FALSE;
		pmime->content_begin = NULL;
		pmime->content_length = 0;
		pmime->mime_type = mime_type::single;
		strcpy(pmime->content_type, "text/plain");
		return true;
	}

	pmime->head_begin = in_buff;
	pmime->head_length = 0;
	while (current_offset <= length) {
		MIME_FIELD mime_field;
		auto parsed_length = parse_mime_field(in_buff + current_offset,
		                     length - current_offset, &mime_field);
		current_offset += parsed_length;
		if (0 != parsed_length) {
			/* 
			 * record the content-type value and parse the param list of
			 * content-type
			 */
			if (strcasecmp(mime_field.name.c_str(), "Content-Type") == 0) {
				parse_field_value(mime_field.value.c_str(),
					mime_field.value.size(), pmime->content_type,
					std::size(pmime->content_type), f_type_params);
				pmime->mime_type = strncasecmp(pmime->content_type, "multipart/", 10) == 0 ?
				                   mime_type::multiple : mime_type::single;
			} else {
				f_other_fields.emplace_back(std::move(mime_field));
			}
			auto nl_size = newline_size(&in_buff[current_offset], length);
			if (nl_size == 0)
				continue;
			pmime->head_length = current_offset;
			/*
			 * If an empty line is met, end the parse of mail head
			 * and skip the empty line which separates the head and
			 * content.
			 */
			current_offset += nl_size;
			if (current_offset > length) {
				pmime->clear();
				return false;
			} else if (current_offset == length) {
				pmime->content_begin = NULL;
				pmime->content_length = 0;
				if (pmime->mime_type == mime_type::multiple)
					pmime->mime_type = mime_type::single;
			} else {
				pmime->content_begin = in_buff + current_offset;
				pmime->content_length = length - current_offset;
			}
			if (pmime->mime_type == mime_type::multiple) {
				std::string bd;
				if (!pmime->get_content_param("boundary", bd))
					pmime->mime_type = mime_type::single;
				gx_strlcpy(pmime->boundary_string, bd.c_str(), std::size(pmime->boundary_string));
				if (!mime_parse_multiple(pmime))
					pmime->mime_type = mime_type::single;
			} else if (pmime->mime_type == mime_type::none) {
				/* old simplest unix style mail */
				strcpy(pmime->content_type, "text/plain");
				pmime->mime_type = mime_type::single;
			}
			return true;
		}
		/*
		 * So now we have something that did not look like a header.
		 * Are we already in content? (Assume yes.)
		 */

		if (0 == current_offset) {
			pmime->head_touched = TRUE;
			pmime->content_begin = in_buff;
			pmime->content_length = length;
			/* old simplest unix style mail */
			strcpy(pmime->content_type, "text/plain");
			pmime->mime_type = mime_type::single;
			return true;
		}
		pmime->head_length = current_offset;

		if (current_offset > length) {
			pmime->clear();
			return false;
		} else if (current_offset == length) {
			pmime->content_begin = NULL;
			pmime->content_length = 0;
			if (pmime->mime_type == mime_type::multiple)
				pmime->mime_type = mime_type::single;
		} else {
			pmime->content_begin = in_buff + current_offset;
			pmime->content_length = length - current_offset;
		}
		if (pmime->mime_type == mime_type::multiple) {
			std::string bd;
			if (!pmime->get_content_param("boundary", bd))
				pmime->mime_type = mime_type::single;
			gx_strlcpy(pmime->boundary_string, bd.c_str(), std::size(pmime->boundary_string));
			if (!mime_parse_multiple(pmime))
				pmime->mime_type = mime_type::single;
		} else if (pmime->mime_type == mime_type::none) {
			strcpy(pmime->content_type,
			       pmime_parent != nullptr &&
			       strcasecmp("multipart/digest", pmime->content_type) == 0 ?
			       "message/rfc822" : "text/plain");
			pmime->mime_type = mime_type::single;
		}
		return true;
	}
	pmime->clear();
	return false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1090: ENOMEM");
	return false;
}

void MIME::clear()
{
	auto pmime = this;
	pmime->mime_type = mime_type::none;
	pmime->content_type[0]	 = '\0';
	pmime->boundary_string[0]= '\0';
	pmime->boundary_len		 = 0;
	pmime->head_touched		 = FALSE;
	pmime->head_begin		 = NULL;
	pmime->head_length		 = 0;
	pmime->content_begin	 = NULL;
	pmime->content_length	 = 0;
	content_buf.reset();
	pmime->first_boundary    = NULL;
    pmime->last_boundary     = NULL;
	pmime->f_type_params.clear();
	pmime->f_other_fields.clear();

}

/*
 *	encode and write the mime content. if this function is invoked, 
 *	original content will be lost! MIME object maintains its own buffer now!
 *	@param
 *		pmime [in,out]		indicate the MIME object
 *		pcontent [in]		pass the content into MIME object
 *		length				length of the object
 *		encoding_type		
 */
bool MIME::write_content(const char *pcontent, size_t length,
    enum mime_encoding encoding_type) try
{
	auto pmime = this;
	/* align the buffer with 64K */
	
#ifdef _DEBUG_UMTA
	if (pcontent == nullptr && length != 0) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	if (pmime->mime_type != mime_type::single &&
	    pmime->mime_type != mime_type::single_obj)
		return false;
	if (encoding_type == mime_encoding::automatic)
		encoding_type = qp_encoded_size_estimate(pcontent, length) < (length / 3 + 1) * 4 ?
		                mime_encoding::qp : mime_encoding::base64;
	if (encoding_type != mime_encoding::base64 &&
	    encoding_type != mime_encoding::qp &&
	    encoding_type != mime_encoding::none) {
		mlog(LV_DEBUG, "mime: encoding type should be one of {none,base64,qp}");
		return false;
	}
	pmime->content_begin = NULL;
	pmime->content_length = 0;
	content_buf.reset();
	pmime->remove_field("Content-Transfer-Encoding");
	if (0 == length) {
		pmime->set_field("Content-Transfer-Encoding",
			encoding_type == mime_encoding::qp ?
			"quoted-printable" : "base64");
		return true;
	}
	switch (encoding_type) {
	case mime_encoding::none: {
		/* should add '\r\n' at the end of buffer if it misses */
		bool added_crlf = pcontent[length-1] != '\n';
		size_t buff_length = strange_roundup(2 * length, 64 * 1024);
		content_buf.reset(me_alloc<char>(buff_length));
		content_begin = content_buf.get();
		if (pmime->content_begin == nullptr)
			return false;
		memcpy(content_buf.get(), pcontent, length);
		pmime->content_length = length;
		if (added_crlf) {
			memcpy(&content_buf[length], "\r\n", 2);
			pmime->content_length += 2;
		}
		return true;
	}
	case mime_encoding::qp: {
		size_t buff_length = strange_roundup(4 * length, 64 * 1024);
		auto pbuff = std::make_unique<char[]>(buff_length);
		content_buf.reset(me_alloc<char>(buff_length));
		content_begin = content_buf.get();
		if (pmime->content_begin == nullptr)
			return false;
		auto qdlen = qp_encode_ex(pbuff.get(), buff_length, pcontent, length);
		if (qdlen < 0)
			return false;
		length = qdlen;
		if (length > 0 && pbuff[length-1] != '\n') {
			memcpy(&pbuff[length], "\r\n", 2);
			length += 2;
		}
		memcpy(content_buf.get(), pbuff.get(), length);
		pmime->content_length = length;
		pmime->set_field("Content-Transfer-Encoding", "quoted-printable");
		return true;
	}
	case mime_encoding::base64: {
		size_t buff_length = strange_roundup(2 * length, 64 * 1024);
		content_buf.reset(me_alloc<char>(buff_length));
		content_begin = content_buf.get();
		if (pmime->content_begin == nullptr)
			return false;
		encode64_ex(pcontent, length, content_buf.get(), buff_length,
				&pmime->content_length);
		pmime->set_field("Content-Transfer-Encoding", "base64");
		return true;
	}
	default:
		break;
	}
	return false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1966: ENOMEM");
	return false;
}

/*
 *	write a mail object into mime
 *	@param
 *		pmime [in]			indicate mime object
 *		pmail [in]			indicate the mail object
 *	@return
 *		TRUE				OK
 *		FALSE				fail
 */
bool MIME::write_mail(MAIL *pmail)
{
	auto pmime = this;
#ifdef _DEBUG_UMTA
	if (pmail == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
    }
#endif
	if (pmime->mime_type != mime_type::single &&
	    pmime->mime_type != mime_type::single_obj)
		return false;
	mime_type = mime_type::single_obj;
	pmime->content_begin = reinterpret_cast<char *>(pmail);
	pmime->content_length = 0;
	content_buf.reset();
	if (!pmime->set_field("Content-Transfer-Encoding", "8bit"))
		return false;
	return true;
}

/*
 *	set the content type of the MIME object
 *	@param
 *		pmime [in,out]		indicate the MIME object
 *		content_type [in]	buffer containing content type
 */
bool MIME::set_content_type(const char *newtype)
{
	auto pmime = this;
	BOOL b_multiple;

#ifdef _DEBUG_UMTA
	if (newtype == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	
	b_multiple = FALSE;
	if (strncasecmp(newtype, "multipart/", 10) == 0)
		b_multiple = TRUE;
	if (pmime->mime_type == mime_type::single ||
	    pmime->mime_type == mime_type::single_obj) {
		if (b_multiple)
			return false;
	} else if (pmime->mime_type == mime_type::none) {
		if (b_multiple) {
			mime_produce_boundary(pmime);
			pmime->mime_type = mime_type::multiple;
		} else {
			pmime->mime_type = mime_type::single;
		}
	}
	gx_strlcpy(content_type, newtype, std::size(content_type));
	pmime->head_touched = TRUE;
	return true;
}

/*
 *	enumerate the field of MIME object
 *	@param
 *		pmime [in,out]		indicate the MIME object
 *		enum_func			enumeration function
 *		pparam				paramerter for enum_func
  *	@return
 *		TRUE				OK to enumerate
 *		FALSE				fail to enumerate
 */		
bool MIME::enum_field(MIME_FIELD_ENUM enum_func, void *pparam) const
{
	auto pmime = this;
	if (!enum_func("Content-Type", pmime->content_type, pparam))
		return false;
	for (const auto &[k, v] : f_other_fields)
		if (!enum_func(k.c_str(), v.c_str(), pparam))
			return false;
	return true;
}

static bool mime_get_content_type_field(const MIME *pmime, char *value, size_t length)
{
	auto offset = strlen(pmime->content_type);
	if (offset >= length)
		return false;
	memcpy(value, pmime->content_type, offset);
	for (const auto &[k, v] : pmime->f_type_params) {
		/* content-type: xxxxx"; "yyyyy */
		if (offset + 4 + k.size() >= length)
			return false;
		memcpy(value + offset, "; ", 2);
		offset += 2;
		memcpy(&value[offset], k.c_str(), k.size());
		offset += k.size();
		/* content_type: xxxxx; yyyyy=zzz */
		if (!v.empty()) {
			if (offset + v.size() + 1 >= length)
				return false;
			value[offset++] = '=';
			memcpy(&value[offset], v.c_str(), v.size());
			offset += v.size();
		}
	}
	value[offset] = '\0';
	return true;
}

/*
 *	get the field of MIME object
 *	@param
 *		pmime [in,out]		indicate the MIME object
 *		tag	[in]			tag of MIME field
 *		value [out]			buffer for retrieving the value of field
 *		length				length of value buffer
 *	@return
 *		TRUE				OK to get value
 *		FALSE				no such tag in fields
 */		
bool MIME::get_field(const char *tag, char *value, size_t length) const
{
	auto pmime = this;
#ifdef _DEBUG_UMTA
	if (tag == nullptr || value == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	if (strcasecmp(tag, "Content-Type") == 0)
		return mime_get_content_type_field(pmime, value, length);
	for (const auto &[k, v] : f_other_fields) {
		if (strcasecmp(tag, k.c_str()) == 0) {
			gx_strlcpy(value, v.c_str(), length);
			return true;
		} 
	}
	return false;
}

/*
 *	get the field number in MIME head
 *	@param
 *		pmime [in]			indicate the MIME object
 *		tag [in]			tag string
 *	@return
 *		number of same tags "XXX"
 */
int MIME::get_field_num(const char *tag) const
{
#ifdef _DEBUG_UMTA
	if (tag == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return 0;
	}
#endif
	if (strcasecmp(tag, "Content-Type") == 0)
		return 1;
	size_t i = 0;
	for (const auto &[k, v] : f_other_fields)
		if (strcasecmp(tag, k.c_str()) == 0)
			i ++;
	return i;
		
}

/*
 *	search the field of MIME object
 *	@param
 *		pmime [in,out]		indicate the MIME object
 *		tag	[in]			tag of MIME field
 *		order				index of order, count for 0 ...
 *		value [out]			buffer for retrieving the value of field
 *		length				length of value buffer
 *	@return
 *		TRUE				OK to get value
 *		FALSE				no such tag in fields
 */		
bool MIME::search_field(const char *tag, int order, std::string &value) const try
{
	auto pmime = this;
	int i;
	
#ifdef _DEBUG_UMTA
	if (tag == nullptr || value == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	if (order < 0)
		return false;
	if (0 == strcasecmp(tag, "Content-Type")) {
		if (order != 0)
			return false;
		value = pmime->content_type;
		return true;
	}
	i = -1;
	for (const auto &[k, v] : f_other_fields) {
		if (strcasecmp(tag, k.c_str()) != 0)
			continue;
		i ++;
		if (i == order) {
			value = v;
			return true;
		}
	}
	return false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1739: ENOMEM");
	return false;
}

/*
 *	set the mime field, if the tag is "content-type", the content type and
 *	content type paramerter list is set, but not f_other_fields! 
 *	@param
 *		pmime [in,out]		indicate the MIME object
 *		tag [in]			tag string
 *		value [in]			value string
 *	@return
 *		TRUE				OK
 *		FALSE				fail to det
 */
bool MIME::set_field(const char *tag, const char *value) try
{
	auto pmime = this;
	char	tmp_buff[MIME_FIELD_LEN];
	
#ifdef _DEBUG_UMTA
	if (tag == nullptr || value == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	if (0 == strcasecmp(tag, "Content-Type")) {
		pmime->f_type_params.clear();
		parse_field_value(value, strlen(value), tmp_buff, 256,
			pmime->f_type_params);
		if (!pmime->set_content_type(tmp_buff)) {
			pmime->f_type_params.clear();
			return false;
		}
		return true;
	}
	MIME_FIELD nf = {tag, value};
	auto it = std::find_if(f_other_fields.begin(), f_other_fields.end(),
	          [&](const MIME_FIELD &mf) { return strcasecmp(tag, mf.name.c_str()) == 0; });
	if (it == f_other_fields.end())
		f_other_fields.emplace_back(std::move(nf));
	else
		*it = std::move(nf);
	pmime->head_touched = TRUE;
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1091: ENOMEM");
	return false;
}

/*
 *	append the mime field, whether it already exists or not! the tag
 *	cannot be "content-type"
 *	@param
 *		pmime [in,out]		indicate the MIME object
 *		tag [in]			tag string
 *		value [in]			value string
 *	@return
 *		TRUE				OK
 *		FALSE				fail to det
 */
bool MIME::append_field(const char *tag, const char *value) try
{
	auto pmime = this;
	
#ifdef _DEBUG_UMTA
	if (tag == nullptr || value == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	if (strcasecmp(tag, "Content-Type") == 0)
		return false;
	f_other_fields.emplace_back(MIME_FIELD{tag, value});
	pmime->head_touched = TRUE;
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1092: ENOMEM");
	return false;
}

/*
 *	remove the mime field, except the tag is "content-type" 
 *	@param
 *		pmime [in,out]		indicate the MIME object
 *		tag [in]			tag string
 *	@return
 *		TRUE				OK
 *		FALSE				not found
 */
bool MIME::remove_field(const char *tag)
{
	if (strcasecmp(tag, "Content-Type") == 0)
		return false;
	auto mid = std::remove_if(f_other_fields.begin(), f_other_fields.end(),
	           [&](const MIME_FIELD &mf) { return strcasecmp(tag, mf.name.c_str()) == 0; });
	auto found = mid != f_other_fields.end();
	f_other_fields.erase(mid, f_other_fields.end());
	return found;
}

/*
 *	get param of content type
 *	@param
 *		pmime [in,out]		indicate the MIME object
 *		tag [in]			tag string		
 *		value [out]			buffer for retrieving value
 */
bool MIME::get_content_param(const char *tag, std::string &value) const try
{
#ifdef _DEBUG_UMTA
	if (tag == nullptr || value == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	for (const auto &[k, v] : f_type_params) {
		if (strcasecmp(tag, k.c_str()) == 0) {
			value = v;
			return true;
		} 
	}
	return false;
} catch (const std::bad_alloc &) {
	return false;
}

/*
 *	set the param of content type
 *	@param
 *		pmime [in,out]		indicate MIME object
 *		tag [in]			tag string
 *		value [in]			value string
 */
bool MIME::set_content_param(const char *tag, const char *value) try
{
	auto pmime = this;
#ifdef _DEBUG_UMTA
	if (tag == nullptr || value == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	if (0 == strcasecmp(tag, "boundary")) {
		auto bdlen = strlen(value);
		if (bdlen > VALUE_LEN - 3 || bdlen < 3)
			return false;
		if ('"' == value[0]) {
			if (value[bdlen-1] != '"')
				return false;
			gx_strlcpy(boundary_string, value + 1, bdlen - 1);
			boundary_len = bdlen - 2;
		} else {
			memcpy(boundary_string, value, bdlen);
			boundary_string[bdlen] = '\0';
			boundary_len = bdlen;
		}
	}
	auto it = std::find_if(f_type_params.begin(), f_type_params.end(),
	          [&](const kvpair &p) { return strcasecmp(tag, p.name.c_str()) == 0; });
	if (it != f_type_params.end())
		f_type_params.erase(it);
	f_type_params.emplace_back(kvpair{tag, value});
	pmime->head_touched = TRUE;
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1094: ENOMEM");
	return false;
}

/*
 *	write MIME object into stream
 *	@param
 *		pmime [in]		indicate the MIME object
 *		pstream [out]	stream for writing
 *	@return
 *		TRUE			OK to copy out the MIME
 *		FALSE			buffer is too short
 */
bool MIME::serialize(STREAM *pstream) const
{
	auto pmime = this;
	long	len, tmp_len;
	BOOL	has_submime;
	
#ifdef _DEBUG_UMTA
	if (pstream == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	if (pmime->mime_type == mime_type::none)
		return false;
	if (!pmime->head_touched) {
		/* the original buffer contains \r\n */
		if (pmime->head_begin + pmime->head_length + 2 == pmime->content_begin){
			pstream->write(pmime->head_begin, pmime->head_length + 2);
		} else {
			pstream->write(pmime->head_begin, pmime->head_length);
			pstream->write("\r\n", 2);
		}
	} else {	
		for (const auto &[k, v] : f_other_fields) {
			/* xxxxx: yyyyy */
			pstream->write(k.c_str(), k.size());
			pstream->write(": ", 2);
			pstream->write(v.c_str(), v.size());
			/* \r\n */
			pstream->write("\r\n", 2);
		}

		/* Content-Type: xxxxx */
		pstream->write("Content-Type: ", 14);
		len = strlen(pmime->content_type);
		pstream->write(pmime->content_type, len);
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		for (const auto &[k, v] : f_type_params) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			pstream->write(";\r\n\t", 4);
			pstream->write(k.c_str(), k.size());
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (v.empty())
				continue;
			pstream->write("=", 1);
			pstream->write(v.c_str(), v.size());
		}
		/* \r\n for separate head and content */
		pstream->write("\r\n\r\n", 4);
	}
	if (pmime->mime_type == mime_type::single ||
	    pmime->mime_type == mime_type::single_obj) {
		if (pmime->content_begin == nullptr)
			/* if there's nothing, just append an empty line */
			pstream->write("\r\n", 2);
		else if (pmime->content_length != 0)
			pstream->write(pmime->content_begin, pmime->content_length);
		return true;
	} else if (pmime->mime_type == mime_type::single_obj) {
		if (pmime->content_begin == nullptr)
			/* well that's not supposed to happen */
			pstream->write("\r\n", 2);
		else if (!pmime->get_mail_ptr()->serialize(pstream))
			return false;
		return true;
	}
	if (pmime->first_boundary == nullptr)
		pstream->write("This is a multi-part message in MIME format.\r\n\r\n", 48);
	else
		pstream->write(pmime->content_begin, pmime->first_boundary - pmime->content_begin);
	auto pnode = pmime->stree.get_child();
	has_submime = FALSE;
	while (NULL != pnode) {
		has_submime = TRUE;
		pstream->write("--", 2);
		pstream->write(pmime->boundary_string, pmime->boundary_len);
		pstream->write("\r\n", 2);
		if (!static_cast<const MIME *>(pnode->pdata)->serialize(pstream))
			return false;
		pnode = pnode->get_sibling();
	}
	if (!has_submime) {
		pstream->write("--", 2);
		pstream->write(pmime->boundary_string, pmime->boundary_len);
		pstream->write("\r\n\r\n", 4);
	}
	pstream->write("--", 2);
	pstream->write(pmime->boundary_string, pmime->boundary_len);
	pstream->write("--", 2);
	if (NULL == pmime->last_boundary) {
		pstream->write("\r\n", 2);
		return true;
	}
	tmp_len = pmime->content_length -
	          (pmime->last_boundary - pmime->content_begin);
	if (tmp_len > 0)
		pstream->write(pmime->last_boundary, tmp_len);
	else if (tmp_len == 0)
		pstream->write("\r\n", 2);
	else
		mlog(LV_DEBUG, "Unspecific error in %s", __PRETTY_FUNCTION__);
	return true;
}

static bool mime_read_multipart_content(const MIME *pmime,
	char *out_buff, size_t *plength)
{
	void *ptr;
	size_t offset, tmp_len;
	unsigned int buff_size;
	BOOL has_submime;
	
	auto tmp_size = pmime->get_length();
	if (tmp_size < 0) {
		*plength = 0;
		return false;
	}
	STREAM tmp_stream;
	if (pmime->first_boundary == nullptr)
		tmp_stream.write("This is a multi-part message in MIME format.\r\n\r\n", 48);
	else
		tmp_stream.write(pmime->content_begin, pmime->first_boundary - pmime->content_begin);
	auto pnode = pmime->stree.get_child();
	has_submime = FALSE;
	while (NULL != pnode) {
		has_submime = TRUE;
		tmp_stream.write("--", 2);
		tmp_stream.write(pmime->boundary_string, pmime->boundary_len);
		tmp_stream.write("\r\n", 2);
		if (!static_cast<MIME *>(pnode->pdata)->serialize(&tmp_stream))
			return false;
		pnode = pnode->get_sibling();
	}
	if (!has_submime) {
		tmp_stream.write("--", 2);
		tmp_stream.write(pmime->boundary_string, pmime->boundary_len);
		tmp_stream.write("\r\n\r\n", 4);
	}
	tmp_stream.write("--", 2);
	tmp_stream.write(pmime->boundary_string, pmime->boundary_len);
	tmp_stream.write("--", 2);
	if (NULL == pmime->last_boundary) {
		tmp_stream.write("\r\n\r\n", 4);
	} else {
		tmp_len = pmime->content_length -
				(pmime->last_boundary - pmime->content_begin);
		if (tmp_len > 0)
			tmp_stream.write(pmime->last_boundary, tmp_len);
		else if (tmp_len == 0)
			tmp_stream.write("\r\n", 2);
	}
	offset = 0;
	buff_size = STREAM_BLOCK_SIZE;
	while ((ptr = tmp_stream.get_read_buf(&buff_size)) != nullptr) {
		memcpy(out_buff + offset, ptr, buff_size);
		offset += buff_size;
		buff_size = STREAM_BLOCK_SIZE;
	}
	*plength = offset;
	return true;
}

/*
 *	write MIME head into buffer
 *	@param
 *		pmime [in]			indicate the MIME object
 *		out_buff [out]		buffer for retrieving the decoded content
 *		plength [in, out]	length of out_buff, and result length
 *	@return
 *		TRUE			OK
 *		FALSE			fail
 */
bool MIME::read_head(char *out_buff, size_t *plength) const
{
	auto pmime = this;
	size_t	len, offset;
	char	tmp_buff[MIME_FIELD_LEN + MIME_NAME_LEN + 4];
	
	if (pmime->mime_type == mime_type::none) {
#ifdef _DEBUG_UMTA
		mlog(LV_DEBUG, "mime: mime content type is not set");
#endif
		return false;
	}
	if (!pmime->head_touched){
		if (pmime->head_length + 2 > *plength) {
			*plength = 0;
			return false;
		}
		*plength = 0;
		if (pmime->head_begin != nullptr) {
			memcpy(out_buff, pmime->head_begin, pmime->head_length);
			*plength += pmime->head_length;
		}
		memcpy(&out_buff[*plength], "\r\n", 2);
		*plength += 2;
		return true;
	}
	offset = 0;
	for (const auto &[k, v] : f_other_fields) {
		/* xxxxx: yyyyy */
		auto res = fmt::format_to_n(tmp_buff, std::size(tmp_buff), "{}: {}\r\n", k, v);
		len = res.size;
		if (offset + len > *plength) {
			*plength = 0;
			return false;
		}
		memcpy(&out_buff[offset], tmp_buff, len);
		offset += len;
	}
	/* Content-Type: xxxxx */
	memcpy(tmp_buff, "Content-Type: ", 14);
	len = 14;
	auto val_len = strlen(pmime->content_type);
	memcpy(tmp_buff + len, pmime->content_type, val_len);
	len += val_len;
	/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
	for (const auto &[k, v] : f_type_params) {
		/* content-type: xxxxx"; \r\n\t"yyyyy */
		if (len > MIME_FIELD_LEN + MIME_NAME_LEN - k.size())
			return false;
		memcpy(tmp_buff + len, ";\r\n\t", 4);
		len += 4;
		memcpy(&tmp_buff[len], k.c_str(), k.size());
		len += k.size();
		if (len > MIME_FIELD_LEN + MIME_NAME_LEN + 3 - v.size())
			return false;
		/* content_type: xxxxx; \r\n\tyyyyy=zzz */
		if (v.empty())
			continue;
		memcpy(&tmp_buff[len], "=", 1);
		len += 1;
		memcpy(&tmp_buff[len], v.c_str(), v.size());
		len += v.size();
	}
	if (len > MIME_FIELD_LEN + MIME_NAME_LEN)
		return false;
	/* \r\n for separate head and content */
	memcpy(tmp_buff + len, "\r\n\r\n", 4);
	len += 4;
	if (offset + len > *plength) {
		*plength = 0;
		return false;
	}
	memcpy(&out_buff[offset], tmp_buff, len);
	offset += len;
	*plength = offset;
	return true;
}

/*
 *	write MIME content into buffer
 *	@param
 *		pmime [in]			indicate the MIME object
 *		out_buff [out]		buffer for retrieving the decoded content
 *		plength [in, out]	length of out_buff, and result length
 *
 * The buffer is filled exactly: *plength is updated with the bytes that were
 * written, and it is unspecified whether a final \0 is generated. (In any
 * case, the returned length never includes \0.)
 *
 * read_content will unpack the Content-Transfer-Encoding.
 * If you do not want that, do not exercise read_content, but use
 * pmime->content_begin directly.
 */
bool MIME::read_content(char *out_buff, size_t *plength) const try
{
	auto pmime = this;
	void *ptr;
	size_t offset, max_length;
	unsigned int buff_size;
	
#ifdef _DEBUG_UMTA
	if (out_buff == nullptr || plength == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	max_length = *plength;
	if (max_length > 0)
		*out_buff = '\0';
	if (pmime->mime_type == mime_type::none) {
		*plength = 0;
		return false;
	}
	if (pmime->mime_type == mime_type::multiple)
		return mime_read_multipart_content(pmime, out_buff, plength);
	if (*plength <= 0) {
		*plength = 0;
		return false;
	}
	if (NULL == pmime->content_begin) {
		*plength = 0;
		return true;
	}
	
	/* content is an email object */
	if (pmime->mime_type == mime_type::single_obj) {
		auto mail_len = pmime->get_mail_ptr()->get_length();
		if (mail_len <= 0) {
			mlog(LV_DEBUG, "Failed to get mail length in %s", __PRETTY_FUNCTION__);
			*plength = 0;
			return false;
		}
		if (static_cast<size_t>(mail_len) >= max_length) {
			*plength = 0;
			return false;
		}
		STREAM tmp_stream;
		if (!pmime->get_mail_ptr()->serialize(&tmp_stream)) {
			*plength = 0;
			return false;
		}
		offset = 0;
		buff_size = STREAM_BLOCK_SIZE;
		while ((ptr = tmp_stream.get_read_buf(&buff_size)) != nullptr) {
			memcpy(out_buff + offset, ptr, buff_size);
			offset += buff_size;
			buff_size = STREAM_BLOCK_SIZE;
		}
		out_buff[offset] = '\0';
		*plength = offset;
		return true;
	}
	char encoding[256];
	enum mime_encoding encoding_type = mime_encoding::unknown;
	if (!pmime->get_field("Content-Transfer-Encoding", encoding, 256)) {
		encoding_type = mime_encoding::none;
	} else {
		HX_strrtrim(encoding);
		HX_strltrim(encoding);

		if (strcasecmp(encoding, "base64") == 0)
			encoding_type = mime_encoding::base64;
		else if (strcasecmp(encoding, "quoted-printable") == 0)
			encoding_type = mime_encoding::qp;
	}
	
	/*
	 * Newline before boundary string or end of mail should not be included
	 * (the mention is hidden somewhere in RFC 2046,2049)
	 */
	size_t tmp_len = pmime->content_length;
	if (tmp_len >= 2 && newline_size(&pmime->content_begin[tmp_len-2], 2) == 2)
		tmp_len -= 2;
	else if (tmp_len >= 1 && newline_size(&pmime->content_begin[tmp_len-1], 1) == 1)
		tmp_len -= 1;
	size_t size = 0;
	auto pbuff = std::make_unique<char[]>(tmp_len);
	memcpy(pbuff.get(), content_begin, tmp_len);
	size = tmp_len;
	
	switch (encoding_type) {
	case mime_encoding::base64:
		if (decode64_ex(pbuff.get(), size, out_buff, max_length, plength) != 0) {
			mlog(LV_DEBUG, "mime: failed to decode base64 mime content");
			if (*plength == 0)
				return false;
		}
		return true;
	case mime_encoding::qp: {
		auto qdlen = qp_decode_ex(out_buff, max_length, pbuff.get(), size);
		if (qdlen < 0)
			goto COPY_RAW_DATA;
		*plength = qdlen;
		return true;
	}
	default:
 COPY_RAW_DATA:
		if (max_length >= size) {
			memcpy(out_buff, pbuff.get(), size);
			*plength = size;
			return true;
		}
		*plength = 0;
		return false;
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1973: Failed to allocate memory");
	*plength = 0;
	return false;
}

/*
 *	calculate MIME length in bytes (no trailing \0 included)
 *	@param
 *		pmime [in]		indicate the MIME object
 *	@return
 *		length of mime object
 */
ssize_t MIME::get_length() const
{
	auto pmime = this;
	BOOL	has_submime;
	
	if (pmime->mime_type == mime_type::none)
		return -1;
	size_t mime_len = 0;
	if (!pmime->head_touched) {
		/* the original buffer contains \r\n */
		mime_len += pmime->head_length + 2;
	} else {	
		for (const auto &[k, v] : f_other_fields)
			/* xxxxx: yyyyy */
			mime_len += k.size() + 2 + v.size() + 2;

		/* Content-Type: xxxxx */
		mime_len += 14;
		mime_len += strlen(pmime->content_type);
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		for (const auto &[k, v] : f_type_params) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			mime_len += k.size() + 4;
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (!v.empty())
				mime_len += v.size() + 1;
		}
		/* \r\n for separate head and content */
		mime_len += 4;
	}
	if (pmime->mime_type == mime_type::single) {
		if (pmime->content_begin != nullptr)
			mime_len += pmime->content_length;
		else
			/* if there's nothing, just append an empty line */
			mime_len += 2;
		return std::min(mime_len, static_cast<size_t>(SSIZE_MAX));
	} else if (pmime->mime_type == mime_type::single_obj) {
		if (NULL != pmime->content_begin) {
			auto mgl = pmime->get_mail_ptr()->get_length();
			if (mgl < 0)
				return -1;
			mime_len += mgl;
		} else {
			/* if there's nothing, just append an empty line */
			mime_len += 2;
		}
		return std::min(mime_len, static_cast<size_t>(SSIZE_MAX));
	}
	mime_len += pmime->first_boundary == nullptr ? 48 :
	            pmime->first_boundary - pmime->content_begin;
	auto pnode = pmime->stree.get_child();
	has_submime = FALSE;
	while (NULL != pnode) {
		has_submime = TRUE;
		mime_len += pmime->boundary_len + 4;
		auto mgl = static_cast<const MIME *>(pnode->pdata)->get_length();
		if (mgl < 0)
			return -1;
		mime_len += mgl;
		pnode = pnode->get_sibling();
	}
	if (!has_submime)
		mime_len += pmime->boundary_len + 6;
	mime_len += pmime->boundary_len + 4;
	if (NULL == pmime->last_boundary) {
		mime_len += 2;
	} else {
		auto tmp_len = pmime->content_length - (pmime->last_boundary -
		               pmime->content_begin);
		if (tmp_len > 0)
			mime_len += tmp_len;
		else if (tmp_len == 0)
			mime_len += 2;
	}
	return std::min(mime_len, static_cast<size_t>(SSIZE_MAX));
}

bool MIME::get_filename(std::string &file_name) const
{
	static constexpr size_t fnsize = 1024;
	char cdname[fnsize];
	auto pmime = this;
	
	if (pmime->get_content_param("name", file_name)) {
		;
	} else if (pmime->get_field("Content-Disposition", cdname, fnsize)) {
		const char *pbegin = strcasestr(cdname, "filename=");
		if (pbegin == nullptr)
			return false;
		pbegin += 9;
		const char *pend = strchr(pbegin, ';');
		if (pend == nullptr)
			file_name.assign(pbegin);
		else
			file_name.assign(pbegin, pend - pbegin);
	} else {
		return false;
	}
	
	HX_strrtrim(file_name.data());
	HX_strltrim(file_name.data());
	auto tmp_len = file_name.size();
	if (('"' == file_name[0] && '"' == file_name[tmp_len - 1]) ||
		('\'' == file_name[0] && '\'' == file_name[tmp_len - 1])) {
		file_name.pop_back();
		file_name.erase(0, 1);
	}
	return !file_name.empty();
}

static int make_digest_single(const MIME *, const char *id, size_t *ofs, size_t head_ofs, Json::Value &);
static int make_digest_multi(const MIME *, const char *id, size_t *ofs, Json::Value &);

/*
 *  get the digest string of mail mime
 *  @param
 *      pmime [in]          indicate the mime object
 *      id_string[in]       id string
 *      poffset[in, out]    offset in mail
 *  @return
 *      string length in pbuff
 */
int MIME::make_mimes_digest(const char *id_string, size_t *poffset,
    Json::Value &dsarray) const try
{
	auto pmime = this;
#ifdef _DEBUG_UMTA
	if (poffset == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return -1;
	}
#endif
	if (pmime->mime_type == mime_type::none)
		return -1;
	/* This function must produce *exactly* the same bytecount as MIME::emit */
	size_t head_offset = *poffset;
	if (!pmime->head_touched) {
		/* the original buffer contains \r\n */
		*poffset += pmime->head_length + 2;
	} else {	
		for (const auto &[k, v] : f_other_fields)
			/* xxxxx: yyyyy */
			*poffset += k.size() + 2 + v.size() + 2;

		/* Content-Type: xxxxx */
		*poffset += 14;
		*poffset += strlen(pmime->content_type);
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		for (const auto &[k, v] : f_type_params) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			*poffset += k.size() + 4;
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (!v.empty())
				*poffset += v.size() + 1;
		}
		/* \r\n for separate head and content */
		*poffset += 4;
	}
	return pmime->mime_type == mime_type::single ||
	       pmime->mime_type == mime_type::single_obj ?
	       make_digest_single(this, id_string, poffset, head_offset, dsarray) :
	       make_digest_multi(this, id_string, poffset, dsarray);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1132: ENOMEM");
	return -1;
}

static void replace_qb(char *s)
{
	for (; *s != '\0'; ++s)
		if (*s == '"' || *s == '\\')
			*s = ' ';
}

static int make_digest_single(const MIME *pmime, const char *id_string,
    size_t *poffset, size_t head_offset, Json::Value &dsarray)
{
	size_t content_len = 0;
	char content_type[256], encoding_buff[128];
	char temp_buff[512], content_ID[128];
	char content_location[256], content_disposition[256], *ptoken;

	strcpy(content_type, pmime->content_type);
	if (!str_isasciipr(content_type))
		strcpy(content_type, "application/octet-stream");
	replace_qb(content_type);
	HX_strrtrim(content_type);
	HX_strltrim(content_type);

	Json::Value digest;
	digest["id"]    = id_string;
	digest["ctype"] = content_type;
	digest["head"]  = Json::Value::UInt64(head_offset);
	digest["begin"] = Json::Value::UInt64(*poffset);
	if (!pmime->get_field("Content-Transfer-Encoding", encoding_buff, 128) ||
	    !str_isasciipr(encoding_buff)) {
		digest["encoding"] = "8bit";
	} else {
		replace_qb(encoding_buff);
		HX_strrtrim(encoding_buff);
		HX_strltrim(encoding_buff);
		digest["encoding"] = encoding_buff;
	}

	if (NULL != pmime->content_begin) {
		if (pmime->mime_type == mime_type::single) {
			*poffset += pmime->content_length;
			content_len = pmime->content_length;
		} else if (pmime->mime_type == mime_type::single_obj) {
			auto mgl = pmime->get_mail_ptr()->get_length();
			if (mgl < 0)
				return -1;
			*poffset += mgl;
			content_len = mgl;
		}
	} else {
		/* if there's nothing, just append an empty line */
		*poffset += 2;
		content_len = 0;
	}

	digest["length"] = Json::Value::UInt64(content_len);
	std::string charset;
	if (pmime->get_content_param("charset", charset) &&
	    str_isasciipr(charset.c_str())) {
		replace_qb(charset.data());
		HX_strrtrim(charset.data());
		HX_strltrim(charset.data());
		charset.resize(strlen(charset.c_str()));
		digest["charset"] = std::move(charset);
	}

	std::string file_name;
	if (pmime->get_filename(file_name))
		digest["filename"] = base64_encode(std::move(file_name));
	if (pmime->get_field("Content-Disposition", content_disposition, 256)) {
		ptoken = strchr(content_disposition, ';');
		if (ptoken != nullptr)
			*ptoken = '\0';
		HX_strrtrim(content_disposition);
		HX_strltrim(content_disposition);
		if ('\0' != content_disposition[0] &&
		    str_isasciipr(content_disposition)) {
			replace_qb(content_disposition);
			digest["cntdspn"] = content_disposition;
		}
	}
	if (pmime->get_field("Content-ID", content_ID, 128)) {
		auto tmp_len = strlen(content_ID);
		encode64(content_ID, tmp_len, temp_buff, 256, &tmp_len);
		digest["cid"] = temp_buff;
	}
	if (pmime->get_field("Content-Location", content_location, 256)) {
		auto tmp_len = strlen(content_location);
		encode64(content_location, tmp_len, temp_buff, 512, &tmp_len);
		digest["cntl"] = temp_buff;
	}
	dsarray.append(std::move(digest));
	return 0;
}

static int make_digest_multi(const MIME *pmime, const char *id_string,
    size_t *poffset, Json::Value &dsarray)
{
	int count;
	size_t tmp_len;
	BOOL has_submime;
	char temp_id[64];

	*poffset += pmime->first_boundary == nullptr ? 48 :
	            pmime->first_boundary - pmime->content_begin;
	auto pnode = pmime->stree.get_child();
	has_submime = FALSE;
	count = 1;
	while (NULL != pnode) {
		has_submime = TRUE;
		*poffset += pmime->boundary_len + 4;
		if (*id_string == '\0')
			snprintf(temp_id, 64, "%d", count);
		else
			snprintf(temp_id, 64, "%s.%d", id_string, count);
		auto mime = static_cast<const MIME *>(pnode->pdata);
		if (mime->make_mimes_digest(temp_id, poffset, dsarray) < 0)
			return -1;
		pnode = pnode->get_sibling();
		count++;
	}
	if (!has_submime)
		*poffset += pmime->boundary_len + 6;
	*poffset += pmime->boundary_len + 4;
	if (NULL == pmime->last_boundary) {
		*poffset += 2;
		return 0;
	}
	tmp_len = pmime->content_length - (pmime->last_boundary -
	          pmime->content_begin);
	*poffset += tmp_len > 0 ? tmp_len : 2;
	return 0;
}

static int make_struct_multi(const MIME *, const char *id, size_t *ofs, size_t head_ofs, Json::Value &);

/*
 *  get the digest string of mail struct
 *  @param
 *      pmime [in]          indicate the mime object
 *      id_string[in]       id string
 *      poffset[in, out]    offset in mail
 *  @return
 *      string length in pbuff
 */
int MIME::make_structure_digest(const char *id_string, size_t *poffset,
    Json::Value &dsarray) const try
{
	auto pmime = this;
#ifdef _DEBUG_UMTA
	if (poffset == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return -1;
	}
#endif
	if (pmime->mime_type == mime_type::none)
		return -1;
	size_t head_offset = *poffset;
	if (!pmime->head_touched) {
		/* the original buffer contains \r\n */
		*poffset += pmime->head_length + 2;
	} else {	
		for (const auto &[k, v] : f_other_fields)
			/* xxxxx: yyyyy */
			*poffset += k.size() + 2 + v.size() + 2;

		/* Content-Type: xxxxx */
		*poffset += 14;
		*poffset += strlen(pmime->content_type);
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		for (const auto &[k, v] : f_type_params) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			*poffset += k.size() + 4;
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (!v.empty())
				*poffset += v.size() + 1;
		}
		/* \r\n for separate head and content */
		*poffset += 4;
	}
	if (pmime->mime_type == mime_type::multiple)
		return make_struct_multi(this, id_string, poffset,
		       head_offset, dsarray);
	if (pmime->content_begin == nullptr) {
		/* if there's nothing, just append an empty line */
		*poffset += 2;
		return 0;
	}
	if (pmime->mime_type == mime_type::single) {
		*poffset += pmime->content_length;
		return 0;
	}
	auto mgl = pmime->get_mail_ptr()->get_length();
	if (mgl < 0)
		return -1;
	*poffset += mgl;
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1333: ENOMEM");
	return -1;
}

static int make_struct_multi(const MIME *pmime, const char *id_string,
    size_t *poffset, size_t head_offset, Json::Value &dsarray)
{
	size_t count = 0;
	BOOL	has_submime;
	char temp_id[64], content_type[256];

	strcpy(content_type, pmime->content_type);
	if (!str_isasciipr(content_type))
		strcpy(content_type, "multipart/mixed");
	replace_qb(content_type);
	HX_strrtrim(content_type);
	HX_strltrim(content_type);
	auto mgl = pmime->get_length();
	if (mgl < 0)
		return -1;
	Json::Value digest;
	digest["id"]     = id_string;
	digest["ctype"]  = content_type;
	digest["head"]   = Json::Value::UInt64(head_offset);
	digest["begin"]  = Json::Value::UInt64(*poffset);
	digest["length"] = Json::Value::UInt64(head_offset + mgl - *poffset);
	dsarray.append(std::move(digest));
	*poffset += pmime->first_boundary == nullptr ? 48 :
	            pmime->first_boundary - pmime->content_begin;
	auto pnode = pmime->stree.get_child();
	has_submime = FALSE;
	count = 1;
	while (NULL != pnode) {
		has_submime = TRUE;
		*poffset += pmime->boundary_len + 4;
		if (*id_string == '\0')
			snprintf(temp_id, 64, "%zu", count);
		else
			snprintf(temp_id, 64, "%s.%zu", id_string, count);
		if (static_cast<const MIME *>(pnode->pdata)->make_structure_digest(temp_id,
		    poffset, dsarray) < 0)
			return -1;
		pnode = pnode->get_sibling();
		count++;
	}
	if (!has_submime)
		*poffset += pmime->boundary_len + 6;
	*poffset += pmime->boundary_len + 4;
	if (NULL == pmime->last_boundary) {
		*poffset += 4;
		return 0;
	}
	size_t tmp_len = pmime->content_length - (pmime->last_boundary - pmime->content_begin);
	*poffset += tmp_len > 0 ? tmp_len : 2;
	return 0;
}

static bool mime_parse_multiple(MIME *pmime)
{
	BOOL b_match;
	int boundary_len;

#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	if (pmime->content_begin == nullptr)
		return false;
	boundary_len = strlen(pmime->boundary_string);
	if (boundary_len <= 2)
		return false;
	const char *begin = strchr(pmime->boundary_string, '"');
	if (NULL != begin) {
		const char *end = strchr(begin + 1, '"');
		if (end == nullptr)
			return false;
		boundary_len = end - begin - 1;
		memmove(pmime->boundary_string, begin + 1, boundary_len);
		pmime->boundary_string[boundary_len] = '\0';
	} 
	pmime->boundary_len = boundary_len;
	
	begin = pmime->content_begin;
	auto end = begin + pmime->content_length - boundary_len;
	auto ptr = begin;
	for (ptr=begin; ptr < end; ptr++) {
		if (ptr[0] != '-' || ptr[1] != '-' ||
		    strncmp(pmime->boundary_string, ptr + 2, boundary_len) != 0)
			continue;
		auto nl_len = newline_size(&ptr[boundary_len+2], 2);
		if (nl_len > 0)
			break;
	}
	if (ptr == end)
		return false;
	pmime->first_boundary = ptr;

	begin = pmime->content_begin + boundary_len;
	end = pmime->content_begin + pmime->content_length - 1;
	b_match = FALSE;
	for (ptr=end; ptr>begin; ptr--) {
		if ('-' == *ptr && '-' == *(ptr - 1) && 
			'-' == *(ptr - 2 - boundary_len) &&
			'-' == *(ptr - 3 - boundary_len)) {
			if (0 == strncasecmp(pmime->boundary_string, 
				ptr - 1 - boundary_len, boundary_len)) {
				b_match = TRUE;
				break;
			}
		}
	}
	if (b_match) {
		pmime->last_boundary = ptr + 1;
		return true;
	}
	pmime->last_boundary = pmime->content_begin + pmime->content_length;
	if (pmime->last_boundary < pmime->first_boundary +
		pmime->boundary_len + 4) {
		return false;
	}
	return true;
}

static void mime_produce_boundary(MIME *pmime)
{
	char *begin, *end, *ptr;
	char temp_boundary[VALUE_LEN];
    int boundary_len;


#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return;
	}
#endif
	int depth = pmime->stree.get_depth();
	strcpy(pmime->boundary_string, "----=_NextPart_");
	auto length = sprintf(pmime->boundary_string + 15, "00%d_000%d_",
				depth, depth + 5);
	begin = pmime->boundary_string + 15 + length;
	end = begin + 8;
	for (ptr=begin; ptr<end; ptr++) {
		char temp = gromox::rand() % 16;
		*ptr = (temp > 9)?(temp + 55):(temp + 48);
	}
	*ptr = '.';
	begin = end + 1;
	end = begin + 8;
	for (ptr=begin; ptr<end; ptr++) {
		char temp = gromox::rand() % 16;
        *ptr = (temp > 9)?(temp + 55):(temp + 48);
    }
	*ptr = '\0';
	
	boundary_len = ptr - pmime->boundary_string;
	pmime->boundary_len = boundary_len;
	temp_boundary[0] = '"';
    memcpy(temp_boundary + 1, pmime->boundary_string, boundary_len);
    temp_boundary[boundary_len] = '"';
    temp_boundary[boundary_len + 1] = '\0';
	pmime->set_content_param("boundary", temp_boundary);
}

MIME *MIME::get_child()
{
	auto pmime = this;
	auto pnode = pmime->stree.get_child();
	return pnode != nullptr ? static_cast<MIME *>(pnode->pdata) : nullptr;
}

MIME *MIME::get_parent()
{
	auto pmime = this;
	auto pnode = pmime->stree.get_parent();
	return pnode != nullptr ? static_cast<MIME *>(pnode->pdata) : nullptr;
}

MIME *MIME::get_sibling()
{
	auto pmime = this;
	auto pnode = pmime->stree.get_sibling();
	return pnode != nullptr ? static_cast<MIME *>(pnode->pdata) : nullptr;
}

const MIME *MIME::get_child() const { return deconst(this)->get_child(); }
const MIME *MIME::get_parent() const { return deconst(this)->get_parent(); }
const MIME *MIME::get_sibling() const { return deconst(this)->get_sibling(); }
