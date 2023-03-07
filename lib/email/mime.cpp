// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 * normally, MIME object does'n maintain its own content buffer, it just take
 * the reference of a mail object buffer, mark the begin, end and the content
 * point. if the user uses the MIME::write_content function, the MIME object
 * will then maintain its own buffer.
 */
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <utility>
#include <libHX/string.h>
#include <gromox/fileio.h>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mime.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>

using namespace gromox;

static bool mime_parse_multiple(MIME *);
static void mime_produce_boundary(MIME *pmime);
static bool mime_check_ascii_printable(const char *s);

bool MAIL::set_header(const char *hdr, const char *val)
{
	auto mail = this;
	auto node = mail->tree.get_root();
	if (node == nullptr)
		return false;
	return static_cast<MIME *>(node->pdata)->set_field(hdr, val);
}

MIME::MIME(alloc_limiter<file_block> *palloc)
{
	auto pmime = this;
#ifdef _DEBUG_UMTA
	if (palloc == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return;
	}
#endif
	pmime->node.pdata		 = pmime;
	mem_file_init(&pmime->f_type_params, palloc);
	mem_file_init(&pmime->f_other_fields, palloc);
}

MIME::~MIME()
{
	auto pmime = this;

	if (pmime->mime_type == mime_type::multiple) {
		auto pnode = pmime->node.get_child();
        while (NULL != pnode) {
			delete static_cast<MIME *>(pnode->pdata);
			pnode = pnode->get_sibling();
        }
	}
	mem_file_free(&pmime->f_type_params);
	mem_file_free(&pmime->f_other_fields);
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
bool MIME::load_from_str_move(MIME *pmime_parent, char *in_buff, size_t length)
{
	auto pmime = this;
	size_t current_offset = 0;
	MIME_FIELD mime_field;

#ifdef _DEBUG_UMTA
	if (in_buff == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	
	pmime->clear();
	if (0 == length) {
		/* in case of NULL content, we think such MIME
		 * is a NULL application/octet-stream
		 */
		pmime->head_touched = FALSE;
		pmime->content_begin = NULL;
		pmime->content_length = 0;
		pmime->mime_type = mime_type::single;
		return true;
	}
	while (current_offset <= length) {
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
					std::size(pmime->content_type),
						&pmime->f_type_params);
				pmime->mime_type = strncasecmp(pmime->content_type, "multipart/", 10) == 0 ?
				                   mime_type::multiple : mime_type::single;
			} else {
				uint32_t v = mime_field.name.size();
				pmime->f_other_fields.write(&v, sizeof(v));
				pmime->f_other_fields.write(mime_field.name.c_str(), v);
				v = std::min(static_cast<size_t>(UINT32_MAX), mime_field.value.size());
				pmime->f_other_fields.write(&v, sizeof(v));
				pmime->f_other_fields.write(mime_field.value.c_str(), v);
			}
			auto nl_size = newline_size(&in_buff[current_offset], length);
			if (nl_size == 0)
				continue;
			pmime->head_begin = in_buff;
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
				if (!pmime->get_content_param("boundary",
				    pmime->boundary_string, VALUE_LEN - 1)) {
					pmime->mime_type = mime_type::single;
				}
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
		pmime->head_begin = in_buff;
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
			if (!pmime->get_content_param("boundary",
			    pmime->boundary_string, VALUE_LEN - 1)) {
				pmime->mime_type = mime_type::single;
			}
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
	size_t i, j;
	/* align the buffer with 64K */
	
#ifdef _DEBUG_UMTA
	if (pcontent == nullptr && length != 0) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	if (pmime->mime_type != mime_type::single)
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
		if (NULL == pmime->content_begin) {
			return false;
		}
		for (i=0,j=0; i<length; i++,j++) {
			if ('.' == pcontent[i]) {
				if (0 == i) {
					pmime->content_begin[j] = '.';
					j ++;
				} else if (i > 2 && pcontent[i-1] == '\n' && pcontent[i-2] == '\r') {
					pmime->content_begin[j] = '.';
					j++;
				}
			}
			pmime->content_begin[j] = pcontent[i];
		}
		length = j;
		pmime->content_length = length;
		if (added_crlf) {
			memcpy(pmime->content_begin + length, "\r\n", 2);
			pmime->content_length += 2;
		}
		return true;
	}
	case mime_encoding::qp: {
		size_t buff_length = strange_roundup(4 * length, 64 * 1024);
		auto pbuff = std::make_unique<char[]>(buff_length);
		content_buf.reset(me_alloc<char>(buff_length));
		content_begin = content_buf.get();
		if (NULL == pmime->content_begin) {
			return false;
		}
		auto qdlen = qp_encode_ex(pbuff.get(), buff_length, pcontent, length);
		if (qdlen < 0) {
			return false;
		}
		length = qdlen;
		if (length > 0 && pbuff[length-1] != '\n') {
			memcpy(&pbuff[length], "\r\n", 2);
			length += 2;
		}
		for (i=0,j=0; i<length; i++,j++) {
			if ('.' == pbuff[i]) {
				if (0 == i) {
					pmime->content_begin[j] = '.';
					j ++;
				} else {
					if (i > 2 && '\n' == pbuff[i - 1] &&
						'\r' == pbuff[i - 2]) {
						pmime->content_begin[j] = '.';
						j ++;
					}
				}
			}
			pmime->content_begin[j] = pbuff[i];
		}
		pmime->content_length = j;
		pmime->set_field("Content-Transfer-Encoding", "quoted-printable");
		return true;
	}
	case mime_encoding::base64: {
		size_t buff_length = strange_roundup(2 * length, 64 * 1024);
		content_buf.reset(me_alloc<char>(buff_length));
		content_begin = content_buf.get();
		if (NULL == pmime->content_begin) {
			return false;
		}
		encode64_ex(pcontent, length, pmime->content_begin, buff_length,
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
	if (pmime->mime_type != mime_type::single)
		return false;
	/* content_begin is not NULL and content_length is 0 means mail object */
	pmime->content_begin = reinterpret_cast<char *>(pmail);
	pmime->content_length = 0;
	content_buf.reset();
	pmime->set_field("Content-Transfer-Encoding", "8bit");
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
	if (pmime->mime_type == mime_type::single) {
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
	gx_strlcpy(content_type, newtype, arsizeof(content_type));
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
	int	tag_len, val_len;
	char tmp_tag[MIME_NAME_LEN];
	char tmp_value[MIME_FIELD_LEN];
	
	if (!enum_func("Content-Type", pmime->content_type, pparam))
		return false;
	MEM_FILE fh = pmime->f_other_fields;
	fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (fh.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		fh.read(tmp_tag, tag_len);
		tmp_tag[tag_len] = '\0';
		fh.read(&val_len, sizeof(uint32_t));
		fh.read(tmp_value, val_len);
		tmp_value[val_len] = '\0';
		if (!enum_func(tmp_tag, tmp_value, pparam))
			return false;
	}
	return true;
}

static bool mime_get_content_type_field(const MIME *pmime, char *value, int length)
{
	int offset;
	int tag_len;
	int val_len;
	char tmp_buff[MIME_FIELD_LEN];
	
	offset = strlen(pmime->content_type);
	if (offset >= length) {
		return false;
	}
	memcpy(value, pmime->content_type, offset);
	MEM_FILE fh = pmime->f_type_params;
	fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (fh.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		/* content-type: xxxxx"; "yyyyy */
		if (offset + 4 + tag_len >= length) {
			return false;
		}
		memcpy(value + offset, "; ", 2);
		offset += 2;
		fh.read(tmp_buff, tag_len);
		memcpy(value + offset, tmp_buff, tag_len);
		offset += tag_len;
		fh.read(&val_len, sizeof(uint32_t));
		fh.read(tmp_buff, val_len);
		/* content_type: xxxxx; yyyyy=zzz */
		if (0 != val_len) {
			if (offset + val_len + 1 >= length) {
				return false;
			}
			value[offset] = '=';
			offset ++;
			memcpy(value + offset, tmp_buff, val_len);
			offset += val_len;
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
bool MIME::get_field(const char *tag, char *value, int length) const
{
	auto pmime = this;
	int tag_len, val_len;
	char tmp_buff[MIME_NAME_LEN];
	
#ifdef _DEBUG_UMTA
	if (tag == nullptr || value == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	if (0 == strcasecmp(tag, "Content-Type")) {
		return mime_get_content_type_field(pmime, value, length);
	}
	MEM_FILE fh = pmime->f_other_fields;
	fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (fh.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		fh.read(tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		fh.read(&val_len, sizeof(uint32_t));
		if (0 == strcasecmp(tag, tmp_buff)) {
			length = (length > val_len)?val_len:(length - 1);
			fh.read(value, length);
			value[length] = '\0';
			return true;
		} 
		fh.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
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
	auto pmime = this;
	int i;
	int	tag_len, val_len;
	char tmp_buff[MIME_NAME_LEN];

#ifdef _DEBUG_UMTA
	if (tag == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return 0;
	}
#endif
	if (0 == strcasecmp(tag, "Content-Type")) {
		return 1;
	}
	i = 0;
	MEM_FILE fh = pmime->f_other_fields;
	fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (fh.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		fh.read(tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		fh.read(&val_len, sizeof(uint32_t));
		if (0 == strcasecmp(tag, tmp_buff)) {
			i ++;
		}
		fh.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
	}
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
bool MIME::search_field(const char *tag, int order, char *value, int length) const
{
	auto pmime = this;
	int i;
	int	tag_len, val_len;
	char tmp_buff[MIME_FIELD_LEN];
	
#ifdef _DEBUG_UMTA
	if (tag == nullptr || value == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	if (order < 0) {
		return false;
	}
	if (0 == strcasecmp(tag, "Content-Type")) {
		if (0 == order) {
			strncpy(value, pmime->content_type, length - 1);
			value[length - 1] = '\0';
		} else {
			return false;
		}
	}
	i = -1;
	MEM_FILE fh = pmime->f_other_fields;
	fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (fh.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		fh.read(tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		fh.read(&val_len, sizeof(uint32_t));
		if (0 == strcasecmp(tag, tmp_buff)) {
			i ++;
			if (i == order) {
				length = (length > val_len)?val_len:(length - 1);
				fh.read(value, length);
				value[length] = '\0';
				return true;
			}
		} 
		fh.read(tmp_buff, val_len);
	}
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
bool MIME::set_field(const char *tag, const char *value)
{
	auto pmime = this;
	MEM_FILE file_tmp;
	int		tag_len, val_len;
	char	tmp_buff[MIME_FIELD_LEN];
	BOOL	found_tag = FALSE;
	int		i, mark;
	
#ifdef _DEBUG_UMTA
	if (tag == nullptr || value == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	if (0 == strcasecmp(tag, "Content-Type")) {
		pmime->f_type_params.clear();
		parse_field_value(value, strlen(value), tmp_buff, 256,
			&pmime->f_type_params);
		if (!pmime->set_content_type(tmp_buff)) {
			pmime->f_type_params.clear();
			return false;
		}
		return true;
	}
	pmime->f_other_fields.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mark = -1;
	while (pmime->f_other_fields.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		mark ++;
		pmime->f_other_fields.read(tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		if (0 == strcasecmp(tag, tmp_buff)) {
			found_tag = TRUE;
			break;
		} 
		pmime->f_other_fields.read(&val_len, sizeof(uint32_t));
		pmime->f_other_fields.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
	}
	if (!found_tag) {
		tag_len = strlen(tag);
		val_len = strlen(value);
		pmime->f_other_fields.write(&tag_len, sizeof(uint32_t));
		pmime->f_other_fields.write(tag, tag_len);
		pmime->f_other_fields.write(&val_len, sizeof(uint32_t));
		pmime->f_other_fields.write(value, val_len);
	} else {
		mem_file_init(&file_tmp, pmime->f_other_fields.allocator);
		pmime->f_other_fields.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		i = 0;
		while (pmime->f_other_fields.read(&tag_len,
		       sizeof(uint32_t)) != MEM_END_OF_FILE) {
			pmime->f_other_fields.read(tmp_buff, tag_len);
			if (i != mark) {
				file_tmp.write(&tag_len, sizeof(uint32_t));
				file_tmp.write(tmp_buff, tag_len);
			}
			pmime->f_other_fields.read(&val_len, sizeof(uint32_t));
			pmime->f_other_fields.read(tmp_buff, val_len);
			if (i != mark) {
				file_tmp.write(&val_len, sizeof(uint32_t));
				file_tmp.write(tmp_buff, val_len);
			}
			i ++;
		}
		/* write the new tag-value at the end of mem file */
		tag_len = strlen(tag);
		val_len = strlen(value);
		file_tmp.write(&tag_len, sizeof(uint32_t));
		file_tmp.write(tag, tag_len);
		file_tmp.write(&val_len, sizeof(uint32_t));
		file_tmp.write(value, val_len);
		file_tmp.copy_to(pmime->f_other_fields);
		mem_file_free(&file_tmp);
	}
	pmime->head_touched = TRUE;
	return true;
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
bool MIME::append_field(const char *tag, const char *value)
{
	auto pmime = this;
	int	tag_len, val_len;
	
#ifdef _DEBUG_UMTA
	if (tag == nullptr || value == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	if (0 == strcasecmp(tag, "Content-Type")) {
		return false;
	}
	tag_len = strlen(tag);
	val_len = strlen(value);
	pmime->f_other_fields.write(&tag_len, sizeof(uint32_t));
	pmime->f_other_fields.write(tag, tag_len);
	pmime->f_other_fields.write(&val_len, sizeof(uint32_t));
	pmime->f_other_fields.write(value, val_len);
	pmime->head_touched = TRUE;
	return true;
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
	auto pmime = this;
	BOOL found_tag = false;
	MEM_FILE file_tmp;
	char tmp_buff[MIME_FIELD_LEN];
	int tag_len, val_len;

	if (0 == strcasecmp(tag, "Content-Type")) {
		return false;
	}
	mem_file_init(&file_tmp, pmime->f_other_fields.allocator);
	pmime->f_other_fields.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (pmime->f_other_fields.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		pmime->f_other_fields.read(tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		if (0 == strcasecmp(tag, tmp_buff)) {
			found_tag = TRUE;
			pmime->f_other_fields.read(&val_len, sizeof(uint32_t));
			pmime->f_other_fields.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
		} else {
			file_tmp.write(&tag_len, sizeof(uint32_t));
			file_tmp.write(tmp_buff, tag_len);
			pmime->f_other_fields.read(&val_len, sizeof(uint32_t));
			pmime->f_other_fields.read(tmp_buff, val_len);
			file_tmp.write(&val_len, sizeof(uint32_t));
			file_tmp.write(tmp_buff, val_len);
		}
	}
	if (found_tag)
		file_tmp.copy_to(pmime->f_other_fields);
	mem_file_free(&file_tmp);
	return found_tag;
}

/*
 *	get param of content type
 *	@param
 *		pmime [in,out]		indicate the MIME object
 *		tag [in]			tag string		
 *		value [out]			buffer for retrieving value
 *		length				length of value
 */
bool MIME::get_content_param(const char *tag, char *value, int length) const
{
	auto pmime = this;
	int	tag_len, val_len;
	char	tmp_buff[MIME_FIELD_LEN];
	int		distance;
	
#ifdef _DEBUG_UMTA
	if (tag == nullptr || value == nullptr) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	MEM_FILE fh = pmime->f_type_params;
	fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (fh.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		fh.read(tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		if (0 == strcasecmp(tag, tmp_buff)) {
			fh.read(&val_len, sizeof(uint32_t));
			distance = (val_len > length - 1)?(length - 1):val_len;
			fh.read(value, distance);
			value[distance] = '\0';
			return true;
		} 
		fh.read(&val_len, sizeof(uint32_t));
		fh.read(tmp_buff, val_len);
	}
	return false;
}

/*
 *	set the param of content type
 *	@param
 *		pmime [in,out]		indicate MIME object
 *		tag [in]			tag string
 *		value [in]			value string
 */
bool MIME::set_content_param(const char *tag, const char *value)
{
	auto pmime = this;
	MEM_FILE file_tmp;
	int	tag_len, val_len;
	char	tmp_buff[MIME_FIELD_LEN];
	BOOL	found_tag = FALSE;
	int i, mark;
	
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
	pmime->f_type_params.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mark = -1;
	while (pmime->f_type_params.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		mark ++;
		pmime->f_type_params.read(tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		if (0 == strcasecmp(tag, tmp_buff)) {
			found_tag = TRUE;
			break;
		} 
		pmime->f_type_params.read(&val_len, sizeof(uint32_t));
		pmime->f_type_params.read(tmp_buff, val_len);
	}
	if (!found_tag) {
		tag_len = strlen(tag);
		val_len = strlen(value);
		pmime->f_type_params.write(&tag_len, sizeof(uint32_t));
		pmime->f_type_params.write(tag, tag_len);
		pmime->f_type_params.write(&val_len, sizeof(uint32_t));
		pmime->f_type_params.write(value, val_len);
		pmime->head_touched = TRUE;
		return true;
	}
	mem_file_init(&file_tmp, pmime->f_type_params.allocator);
	pmime->f_type_params.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	i = 0;
	while (pmime->f_type_params.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		pmime->f_type_params.read(tmp_buff, tag_len);
		if (i != mark) {
			file_tmp.write(&tag_len, sizeof(uint32_t));
			file_tmp.write(tmp_buff, tag_len);
		}
		pmime->f_type_params.read(&val_len, sizeof(uint32_t));
		pmime->f_type_params.read(tmp_buff, val_len);
		if (i != mark) {
			file_tmp.write(&val_len, sizeof(uint32_t));
			file_tmp.write(tmp_buff, val_len);
		}
		i ++;
	}
	/* write the new tag-value at the end of mem file */
	tag_len = strlen(tag);
	val_len = strlen(value);
	file_tmp.write(&tag_len, sizeof(uint32_t));
	file_tmp.write(tag, tag_len);
	file_tmp.write(&val_len, sizeof(uint32_t));
	file_tmp.write(value, val_len);
	file_tmp.copy_to(pmime->f_type_params);
	mem_file_free(&file_tmp);
	pmime->head_touched = TRUE;
	return true;
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
	int		tag_len, val_len;
	long	len, tmp_len;
	char	tmp_buff[MIME_FIELD_LEN];
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
		MEM_FILE fh = pmime->f_other_fields;
		fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (fh.read(&tag_len,
		       sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* xxxxx: yyyyy */
			fh.read(tmp_buff, tag_len);
			pstream->write(tmp_buff, tag_len);
			pstream->write(": ", 2);
			fh.read(&val_len, sizeof(uint32_t));
			fh.read(tmp_buff, val_len);
			pstream->write(tmp_buff, val_len);
			/* \r\n */
			pstream->write("\r\n", 2);
		}

		/* Content-Type: xxxxx */
		pstream->write("Content-Type: ", 14);
		len = strlen(pmime->content_type);
		pstream->write(pmime->content_type, len);
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		fh = pmime->f_type_params;
		fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (fh.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			pstream->write(";\r\n\t", 4);
			fh.read(tmp_buff, tag_len);
			pstream->write(tmp_buff, tag_len);
			fh.read(&val_len, sizeof(uint32_t));
			fh.read(tmp_buff, val_len);
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (0 != val_len) {
				pstream->write("=", 1);
				pstream->write(tmp_buff, val_len);
			}
		}
		/* \r\n for separate head and content */
		pstream->write("\r\n\r\n", 4);
	}
	if (pmime->mime_type == mime_type::single) {
		if (pmime->content_begin == nullptr)
			/* if there's nothing, just append an empty line */
			pstream->write("\r\n", 2);
		else if (pmime->content_length != 0)
			pstream->write(pmime->content_begin, pmime->content_length);
		else if (!reinterpret_cast<MAIL *>(pmime->content_begin)->serialize(pstream))
			return false;
		return true;
	}
	if (NULL == pmime->first_boundary) {
		pstream->write("This is a multi-part message in MIME format.\r\n\r\n", 48);
	} else {
		pstream->write(pmime->content_begin, pmime->first_boundary - pmime->content_begin);
	}
	auto pnode = pmime->node.get_child();
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
		pstream->write("\r\n\r\n", 4);
		return true;
	}
	tmp_len = pmime->content_length -
	          (pmime->last_boundary - pmime->content_begin);
	if (tmp_len > 0) {
		pstream->write(pmime->last_boundary, tmp_len);
	} else if (0 == tmp_len) {
		pstream->write("\r\n", 2);
	} else {
		mlog(LV_DEBUG, "Unspecific error in %s", __PRETTY_FUNCTION__);
	}
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
	alloc_limiter<stream_block> pallocator(tmp_size / STREAM_BLOCK_SIZE + 1,
		"mime_read_multipart");
	STREAM tmp_stream(&pallocator);
	if (NULL == pmime->first_boundary) {
		tmp_stream.write("This is a multi-part message in MIME format.\r\n\r\n", 48);
	} else {
		tmp_stream.write(pmime->content_begin, pmime->first_boundary - pmime->content_begin);
	}
	auto pnode = pmime->node.get_child();
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
		if (tmp_len > 0) {
			tmp_stream.write(pmime->last_boundary, tmp_len);
		} else if (0 == tmp_len) {
			tmp_stream.write("\r\n", 2);
		}
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
	uint32_t tag_len, val_len;
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
		memcpy(out_buff, pmime->head_begin, pmime->head_length);
		memcpy(out_buff + pmime->head_length, "\r\n", 2);
		*plength = pmime->head_length + 2;
		return true;
	}
	offset = 0;
	MEM_FILE fh = pmime->f_other_fields;
	fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (fh.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		/* xxxxx: yyyyy */
		fh.read(tmp_buff, tag_len);
		len = tag_len;
		memcpy(tmp_buff + len, ": ", 2);
		len += 2;
		fh.read(&val_len, sizeof(uint32_t));
		fh.read(tmp_buff + len, val_len);
		len += val_len;
		memcpy(tmp_buff + len, "\r\n", 2);
		len += 2;
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
	val_len = strlen(pmime->content_type);
	memcpy(tmp_buff + len, pmime->content_type, val_len);
	len += val_len;
	/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
	fh = pmime->f_type_params;
	fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (fh.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		/* content-type: xxxxx"; \r\n\t"yyyyy */
		if (len > MIME_FIELD_LEN + MIME_NAME_LEN - tag_len) {
			return false;
		}
		memcpy(tmp_buff + len, ";\r\n\t", 4);
		len += 4;
		fh.read(tmp_buff + len, tag_len);
		len += tag_len;
		fh.read(&val_len, sizeof(uint32_t));
		if (len > MIME_FIELD_LEN + MIME_NAME_LEN + 3 - val_len) {
			return false;
		}
		/* content_type: xxxxx; \r\n\tyyyyy=zzz */
		if (0 != val_len) {
			memcpy(tmp_buff + len, "=", 1);
			len += 1;
			fh.read(tmp_buff + len, val_len);
			len += val_len;
		}
	}
	if (len > MIME_FIELD_LEN + MIME_NAME_LEN) {
		return false;
	}
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
 *	@return
 *		TRUE			OK
 *		FALSE			fail
 */
bool MIME::read_content(char *out_buff, size_t *plength) const try
{
	auto pmime = this;
	void *ptr;
	size_t i, offset, max_length;
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
	if (0 == pmime->content_length) {
		auto mail_len = reinterpret_cast<MAIL *>(pmime->content_begin)->get_length();
		if (mail_len <= 0) {
			mlog(LV_DEBUG, "Failed to get mail length in %s", __PRETTY_FUNCTION__);
			*plength = 0;
			return false;
		}
		if (static_cast<size_t>(mail_len) >= max_length) {
			*plength = 0;
			return false;
		}
		alloc_limiter<stream_block> pallocator(mail_len / STREAM_BLOCK_SIZE + 1,
			"mime::read_content");
		STREAM tmp_stream(&pallocator);
		if (!reinterpret_cast<MAIL *>(pmime->content_begin)->serialize(&tmp_stream)) {
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
		if (0 == strcasecmp(encoding, "base64")) {
			encoding_type = mime_encoding::base64;
		} else if (0 == strcasecmp(encoding, "quoted-printable")) {
			encoding_type = mime_encoding::qp;
		} else if (0 == strcasecmp(encoding, "uue") ||
			0 == strcasecmp(encoding, "x-uue") ||
			0 == strcasecmp(encoding, "uuencode") ||
			0 == strcasecmp(encoding, "x-uuencode")) {
			encoding_type = mime_encoding::uuencode;
		}
	}
	
	auto pbuff = std::make_unique<char[]>(((pmime->content_length - 1) / (64 * 1024) + 1) * 64 * 1024);
	/*
	 * Newline before boundary string or end of mail should not be included
	 * (the mention is hidden somewhere in RFC 2046,2049)
	 */
	size_t tmp_len = pmime->content_length;
	if (tmp_len >= 2 && newline_size(&pmime->content_begin[tmp_len-2], 2) == 2) {
		tmp_len -= 2;
	} else if (tmp_len >= 1 && newline_size(&pmime->content_begin[tmp_len-1], 1) == 1) {
		tmp_len -= 1;
	}
	size_t size = 0;
	for (i=0; i<tmp_len; i++) {
		if ('.' == pmime->content_begin[i]) {
			if (0 == i) {
				if ('.' == pmime->content_begin[1]) {
					i ++;
				}
			} else {
				if (i > 2 && '\n' == pmime->content_begin[i - 1] &&
					'\r' == pmime->content_begin[i - 2] &&
					'.' == pmime->content_begin[i + 1]) {
					i ++;
				}
			}
		}
		pbuff[size] = pmime->content_begin[i];
		size ++;
	}
	
	switch (encoding_type) {
	case mime_encoding::base64:
		if (decode64_ex(pbuff.get(), size, out_buff, max_length, plength) != 0) {
			mlog(LV_DEBUG, "mime: failed to decode base64 mime content");
			if (0 == *plength) {
				return false;
			}
		}
		return true;
	case mime_encoding::qp: {
		auto qdlen = qp_decode_ex(out_buff, max_length, pbuff.get(), size);
		if (qdlen < 0) {
			goto COPY_RAW_DATA;
		} else {
			*plength = qdlen;
			return true;
		}
	}
	case mime_encoding::uuencode:
		if (uudecode(pbuff.get(), size, nullptr, nullptr, 0, out_buff,
		    max_length, plength) != 0) {
			mlog(LV_DEBUG, "mime: failed to decode uuencode mime content");
			goto COPY_RAW_DATA;
		}
		return true;
	default:
 COPY_RAW_DATA:
		if (max_length >= size) {
			memcpy(out_buff, pbuff.get(), size);
			*plength = size;
			return true;
		} else {
			*plength = 0;
			return false;
		}
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1973: Failed to allocate memory");
	*plength = 0;
	return false;
}

bool MIME::emit(write_func write, void *fd) const
{
	auto pmime = this;
	BOOL has_submime;
	size_t len, tmp_len;
	int	tag_len, val_len;
	char tmp_buff[MIME_FIELD_LEN + MIME_NAME_LEN + 4];
	
	if (pmime->mime_type == mime_type::none) {
#ifdef _DEBUG_UMTA
		mlog(LV_DEBUG, "mime: mime content type is not set");
#endif
		return false;
	}
	if (!pmime->head_touched) {
		/* the original buffer contains \r\n */
		if (pmime->head_begin + pmime->head_length
			+ 2 == pmime->content_begin) {
			auto wrlen = write(fd, pmime->head_begin, pmime->head_length + 2);
			if (wrlen < 0 || static_cast<size_t>(wrlen) != pmime->head_length + 2)
				return false;
		} else {
			auto wrlen = write(fd, pmime->head_begin, pmime->head_length);
			if (wrlen < 0 || static_cast<size_t>(wrlen) != pmime->head_length)
				return false;
			if (2 != write(fd, "\r\n", 2)) {
				return false;
			}
		}
	} else {	
		MEM_FILE fh = pmime->f_other_fields;
		fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (fh.read(&tag_len,
		       sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* xxxxx: yyyyy */
			fh.read(tmp_buff, tag_len);
			len = tag_len;
			memcpy(tmp_buff + len, ": ", 2);
			len += 2;
			fh.read(&val_len, sizeof(uint32_t));
			fh.read(tmp_buff + len, val_len);
			len += val_len;
			memcpy(tmp_buff + len, "\r\n", 2);
			len += 2;
			auto wrlen = write(fd, tmp_buff, len);
			if (wrlen < 0 || static_cast<size_t>(wrlen) != len)
				return false;
		}

		/* Content-Type: xxxxx */
		memcpy(tmp_buff, "Content-Type: ", 14);
		len = 14;
		val_len = strlen(pmime->content_type);
		memcpy(tmp_buff + len, pmime->content_type, val_len);
		len += val_len;
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		fh = pmime->f_type_params;
		fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (fh.read(&tag_len,
		       sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			if (len > MIME_FIELD_LEN + MIME_NAME_LEN - tag_len) {
				return false;
			}
			memcpy(tmp_buff + len, ";\r\n\t", 4);
			len += 4;
			fh.read(tmp_buff + len, tag_len);
			len += tag_len;
			fh.read(&val_len, sizeof(uint32_t));
			if (len > MIME_FIELD_LEN + MIME_NAME_LEN + 3 - val_len) {
				return false;
			}
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (0 != val_len) {
				memcpy(tmp_buff + len, "=", 1);
				len += 1;
				fh.read(tmp_buff + len, val_len);
				len += val_len;
			}
		}
		if (len > MIME_FIELD_LEN + MIME_NAME_LEN) {
			return false;
		}
		/* \r\n for separate head and content */
		memcpy(tmp_buff + len, "\r\n\r\n", 4);
		len += 4;
		auto wrlen = write(fd, tmp_buff, len);
		if (wrlen < 0 || static_cast<size_t>(wrlen) != len)
			return false;
	}
	if (pmime->mime_type == mime_type::single) {
		if (NULL != pmime->content_begin) {
			if (0 != pmime->content_length) {
				auto wrlen = write(fd, pmime->content_begin, pmime->content_length);
				if (wrlen < 0 || static_cast<size_t>(wrlen) != pmime->content_length)
					return false;
			} else {
				if (!reinterpret_cast<MAIL *>(pmime->content_begin)->emit(write, fd))
					return false;
			}
		} else {
			/* if there's nothing, just append an empty line */
			if (2 != write(fd, "\r\n", 2)) {
				return false;
			}
		}
		return true;
	}
	if (NULL == pmime->first_boundary) {
		if (48 != write(fd, "This is a multi-part message "
		    "in MIME format.\r\n\r\n", 48)) {
			return false;
		}
	} else if (write(fd, pmime->content_begin, pmime->first_boundary - pmime->content_begin) !=
	    pmime->first_boundary - pmime->content_begin) {
		return false;
	}
	auto pnode = pmime->node.get_child();
	has_submime = FALSE;
	while (NULL != pnode) {
		has_submime = TRUE;
		memcpy(tmp_buff, "--", 2);
		len = 2;
		memcpy(tmp_buff + len, pmime->boundary_string,
		       pmime->boundary_len);
		len += pmime->boundary_len;
		memcpy(tmp_buff + len, "\r\n", 2);
		len += 2;
		auto wrlen = write(fd, tmp_buff, len);
		if (wrlen < 0 || static_cast<size_t>(wrlen) != len)
			return false;
		if (!static_cast<const MIME *>(pnode->pdata)->emit(write, fd))
			return false;
		pnode = pnode->get_sibling();
	}
	if (!has_submime) {
		memcpy(tmp_buff, "--", 2);
		len = 2;
		memcpy(tmp_buff + len, pmime->boundary_string,
		       pmime->boundary_len);
		len += pmime->boundary_len;
		memcpy(tmp_buff + len, "\r\n\r\n", 4);
		len += 4;
		auto wrlen = write(fd, tmp_buff, len);
		if (wrlen < 0 || static_cast<size_t>(wrlen) != len)
			return false;
	}
	memcpy(tmp_buff, "--", 2);
	len = 2;
	memcpy(tmp_buff + len, pmime->boundary_string, pmime->boundary_len);
	len += pmime->boundary_len;
	memcpy(tmp_buff + len, "--", 2);
	len += 2;
	if (NULL == pmime->last_boundary) {
		memcpy(tmp_buff + len, "\r\n\r\n", 4);
		len += 4;
	} else {
		tmp_len = pmime->content_length -
		          (pmime->last_boundary - pmime->content_begin);
		if (tmp_len > 0 && tmp_len < sizeof(tmp_buff) - len) {
			memcpy(tmp_buff + len, pmime->last_boundary, tmp_len);
			len +=  tmp_len;
		} else if (0 == tmp_len) {
			memcpy(tmp_buff + len, "\r\n", 2);
			len += 2;
		} else {
			mlog(LV_ERR, "E-1640");
			return false;
		}
	}
	auto wrlen = write(fd, tmp_buff, len);
	if (wrlen < 0 || static_cast<size_t>(wrlen) != len)
		return false;
	return true;
}

/*
 *	check dot-stuffing in MIME object
 *	@param
 *		pmime [in]		indicate the MIME object
 *	@return
 *		TRUE			dot-stuffing in MIME
 *		FALSE			no dot-stuffing in MIME
 */
bool MIME::check_dot() const
{
	auto pmime = this;
	size_t	tmp_len;
	int		tag_len, val_len;
	char	tmp_buff[MIME_FIELD_LEN + MIME_NAME_LEN + 4];
	
	if (pmime->mime_type == mime_type::none) {
#ifdef _DEBUG_UMTA
		mlog(LV_DEBUG, "mime: mime content type is not set");
#endif
		return false;
	}
	if (!pmime->head_touched) {
		if (pmime->head_length >= 2 && (('.' == pmime->head_begin[0] &&
			'.' == pmime->head_begin[1]) || NULL != memmem(
			pmime->head_begin, pmime->head_length, "\r\n..", 4))) {
			return true;
		}
	} else {	
		MEM_FILE fh = pmime->f_other_fields;
		fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (fh.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* xxxxx: yyyyy */
			fh.read(tmp_buff, tag_len);
			if (tag_len >= 2 && '.' == tmp_buff[0] && '.' == tmp_buff[1]) {
				return true;
			}
			fh.read(&val_len, sizeof(uint32_t));
			fh.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
		}
		
	}
	if (pmime->mime_type == mime_type::single) {
		if (pmime->content_begin == nullptr)
			return true;
		if (0 != pmime->content_length) {
			if (pmime->content_length >= 2 &&
				(('.' == pmime->content_begin[0] &&
				'.' == pmime->content_begin[1]) ||
				NULL != memmem(pmime->content_begin,
				pmime->content_length, "\r\n..", 4))) {
				return true;
			}
		} else if (reinterpret_cast<MAIL *>(pmime->content_begin)->check_dot()) {
			return true;
		} 
		return true;
	}
	if (NULL != pmime->first_boundary) {
		tmp_len = pmime->first_boundary - pmime->content_begin;
		if (tmp_len >= 2 && (('.' == pmime->first_boundary[0] &&
		    '.' == pmime->first_boundary[1]) ||
		    NULL != memmem(pmime->first_boundary, tmp_len, "\r\n..", 4))) {
			return true;
		}
	}
	auto pnode = pmime->node.get_child();
	while (NULL != pnode) {
		if (static_cast<const MIME *>(pnode->pdata)->check_dot())
			return true;
		pnode = pnode->get_sibling();
	}
	if (NULL != pmime->last_boundary) {
		tmp_len = pmime->content_length -
		          (pmime->last_boundary - pmime->content_begin);
		if (tmp_len >= 2 && (('.' == pmime->last_boundary[0] &&
		    '.' == pmime->last_boundary[1]) ||
		    NULL != memmem(pmime->last_boundary, tmp_len, "\r\n..", 4))) {
			return true;
		}
	}
	return false;
}

/*
 *	calculate MIME length in bytes
 *	@param
 *		pmime [in]		indicate the MIME object
 *	@return
 *		length of mime object
 */
ssize_t MIME::get_length() const
{
	auto pmime = this;
	int		tag_len, val_len;
	BOOL	has_submime;
	
	if (pmime->mime_type == mime_type::none)
		return -1;
	size_t mime_len = 0;
	if (!pmime->head_touched) {
		/* the original buffer contains \r\n */
		mime_len += pmime->head_length + 2;
	} else {	
		MEM_FILE fh = pmime->f_other_fields;
		fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (fh.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* xxxxx: yyyyy */
			fh.seek(MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
			mime_len += tag_len + 2;
			fh.read(&val_len, sizeof(uint32_t));
			fh.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
			mime_len += val_len + 2;
		}

		/* Content-Type: xxxxx */
		mime_len += 14;
		mime_len += strlen(pmime->content_type);
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		fh = pmime->f_type_params;
		fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (fh.read(&tag_len,
		       sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			mime_len += tag_len + 4;
			fh.seek(MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
			fh.read(&val_len, sizeof(uint32_t));
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (0 != val_len) {
				mime_len += val_len + 1;
				fh.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
			}
		}
		/* \r\n for separate head and content */
		mime_len += 4;
	}
	if (pmime->mime_type == mime_type::single) {
		if (NULL != pmime->content_begin) {
			if (0 != pmime->content_length) {
				mime_len += pmime->content_length;
			} else {
				auto mgl = reinterpret_cast<MAIL *>(pmime->content_begin)->get_length();
				if (mgl < 0)
					return -1;
				mime_len += mgl;
			}
		} else {
			/* if there's nothing, just append an empty line */
			mime_len += 2;
		}
		return std::min(mime_len, static_cast<size_t>(SSIZE_MAX));
	}
	if (NULL == pmime->first_boundary) {
		mime_len += 48;
	} else {
		mime_len += pmime->first_boundary - pmime->content_begin;
	}
	auto pnode = pmime->node.get_child();
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
		mime_len += 4;
	} else {
		auto tmp_len = pmime->content_length - (pmime->last_boundary -
		               pmime->content_begin);
		if (tmp_len > 0) {
			mime_len += tmp_len;
		} else if (0 == tmp_len) {
			mime_len += 2;
		}
	}
	return std::min(mime_len, static_cast<size_t>(SSIZE_MAX));
}

bool MIME::get_filename(char *file_name, size_t fnsize) const
{
	auto pmime = this;
	int mode;
	char *ptr;
	char *pend;
	int tmp_len;
	char *pbegin;
	char encoding[256];
	
	if (pmime->get_content_param("name", file_name, fnsize)) {
		goto FIND_FILENAME;
	} else if (pmime->get_field("Content-Disposition", file_name, fnsize)) {
		tmp_len = strlen(file_name);
		pbegin = search_string(file_name, "filename=", tmp_len);
		if (NULL != pbegin) {
			pbegin += 9;
			pend = strchr(pbegin, ';');
			if (NULL == pend) {
				pend = file_name + tmp_len;
			}
			tmp_len = pend - pbegin;
			memmove(file_name, pbegin, tmp_len);
			file_name[tmp_len] = '\0';
			goto FIND_FILENAME;
		}
		return false;
	} else if (pmime->get_field("Content-Transfer-Encoding",
	    encoding, std::size(encoding))) {
		if (0 == strcasecmp(encoding, "uue") ||
			0 == strcasecmp(encoding, "x-uue") ||
			0 == strcasecmp(encoding, "uuencode") ||
			0 == strcasecmp(encoding, "x-uuencode")) {
			if (0 == pmime->content_length) {
				return false;
			}
			if (pmime->content_length > 128) {
				tmp_len = 128;
			} else {
				tmp_len = pmime->content_length;
			}
			if (pmime->content_begin == nullptr)
				return false;
			ptr = search_string(pmime->content_begin, "begin ", tmp_len);
			if (NULL == ptr) {
				return false;
			}
			ptr += 6;
			if (' ' != ptr[3]) {
				return false;
			}
			if (1 != sscanf(ptr, "%o ", &mode)) {
				return false;
			}
			ptr += 4;
			for (size_t i = 0; i < fnsize; ++i, ++ptr) {
				if ('\r' == *ptr || '\n' == *ptr) {
					ptr ++;
					file_name[i] = '\0';
					goto FIND_FILENAME;
				}
				file_name[i] = *ptr;
			}
		}
	}
	return false;
	
 FIND_FILENAME:
	HX_strrtrim(file_name);
	HX_strltrim(file_name);
	tmp_len = strlen(file_name);
	if (('"' == file_name[0] && '"' == file_name[tmp_len - 1]) ||
		('\'' == file_name[0] && '\'' == file_name[tmp_len - 1])) {
		file_name[tmp_len - 1] = '\0';
		memmove(file_name, file_name + 1, tmp_len - 1);
	}
	if ('\0' == file_name[0]) {
		return false;
	}
	return true;
}

static int mime_get_digest_single(const MIME *, const char *id, size_t *ofs, size_t head_ofs, Json::Value &);
static int mime_get_digest_multi(const MIME *, const char *id, size_t *ofs, Json::Value &);

/*
 *  get the digest string of mail mime
 *  @param
 *      pmime [in]          indicate the mime object
 *      id_string[in]       id string
 *      poffset[in, out]    offset in mail
 *  @return
 *      string length in pbuff
 */
int MIME::get_mimes_digest(const char *id_string, size_t *poffset,
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
		uint32_t tag_len = 0, val_len = 0;
		MEM_FILE fh = pmime->f_other_fields;
		fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (fh.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* xxxxx: yyyyy */
			fh.seek(MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
			*poffset += tag_len + 2;
			fh.read(&val_len, sizeof(uint32_t));
			fh.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
			*poffset += val_len + 2;
		}

		/* Content-Type: xxxxx */
		*poffset += 14;
		*poffset += strlen(pmime->content_type);
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		fh = pmime->f_type_params;
		fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (fh.read(&tag_len,
		       sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			*poffset += tag_len + 4;
			fh.seek(MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
			fh.read(&val_len, sizeof(uint32_t));
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (0 != val_len) {
				*poffset += val_len + 1;
				fh.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
			}
		}
		/* \r\n for separate head and content */
		*poffset += 4;
	}
	return pmime->mime_type == mime_type::single ?
	       mime_get_digest_single(this, id_string, poffset, head_offset, dsarray) :
	       mime_get_digest_multi(this, id_string, poffset, dsarray);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1132: ENOMEM");
	return -1;
}

static int mime_get_digest_single(const MIME *pmime, const char *id_string,
    size_t *poffset, size_t head_offset, Json::Value &dsarray)
{
	size_t i, content_len, tmp_len;
	char charset_buff[32], content_type[256], encoding_buff[128];
	char file_name[256], temp_buff[512], content_ID[128];
	char content_location[256], content_disposition[256], *ptoken;

	strcpy(content_type, pmime->content_type);
	if (!mime_check_ascii_printable(content_type))
		strcpy(content_type, "application/octet-stream");
	tmp_len = strlen(content_type);
	for (i = 0; i < tmp_len; i++) {
		if ('"' == content_type[i] || '\\' == content_type[i]) {
			content_type[i] = ' ';
		}
	}
	HX_strrtrim(content_type);
	HX_strltrim(content_type);

	Json::Value digest;
	digest["id"]    = id_string;
	digest["ctype"] = content_type;
	digest["head"]  = Json::Value::UInt64(head_offset);
	digest["begin"] = Json::Value::UInt64(*poffset);
	if (!pmime->get_field("Content-Transfer-Encoding", encoding_buff, 128) ||
	    !mime_check_ascii_printable(encoding_buff)) {
		digest["encoding"] = "8bit";
	} else {
		tmp_len = strlen(encoding_buff);
		for (i = 0; i < tmp_len; i++) {
			if ('"' == encoding_buff[i] || '\\' == encoding_buff[i]) {
				encoding_buff[i] = ' ';
			}
		}
		HX_strrtrim(encoding_buff);
		HX_strltrim(encoding_buff);
		digest["encoding"] = encoding_buff;
	}

	if (NULL != pmime->content_begin) {
		if (0 != pmime->content_length) {
			*poffset += pmime->content_length;
			content_len = pmime->content_length;
		} else {
			auto mgl = reinterpret_cast<MAIL *>(pmime->content_begin)->get_length();
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
	if (pmime->get_content_param("charset", charset_buff, 32) &&
	    mime_check_ascii_printable(charset_buff)) {
		tmp_len = strlen(charset_buff);
		for (i = 0; i < tmp_len; i++) {
			if ('"' == charset_buff[i] || '\\' == charset_buff[i]) {
				charset_buff[i] = ' ';
			}
		}
		HX_strrtrim(charset_buff);
		HX_strltrim(charset_buff);
		digest["charset"] = charset_buff;
	}

	if (pmime->get_filename(file_name, std::size(file_name))) {
		encode64(file_name, strlen(file_name), temp_buff, 512, &tmp_len);
		digest["filename"] = temp_buff;
	}
	if (pmime->get_field("Content-Disposition", content_disposition, 256)) {
		ptoken = strchr(content_disposition, ';');
		if (NULL != ptoken) {
			*ptoken = '\0';
		}
		HX_strrtrim(content_disposition);
		HX_strltrim(content_disposition);
		if ('\0' != content_disposition[0] &&
		    mime_check_ascii_printable(content_disposition)) {
			tmp_len = strlen(content_disposition);
			for (i = 0; i < tmp_len; i++) {
				if ('"' == content_disposition[i] ||
				    '\\' == content_disposition[i]) {
					content_disposition[i] = ' ';
				}
			}
			digest["cntdspn"] = content_disposition;
		}
	}
	if (pmime->get_field("Content-ID", content_ID, 128)) {
		tmp_len = strlen(content_ID);
		encode64(content_ID, tmp_len, temp_buff, 256, &tmp_len);
		digest["cid"] = temp_buff;
	}
	if (pmime->get_field("Content-Location", content_location, 256)) {
		tmp_len = strlen(content_location);
		encode64(content_location, tmp_len, temp_buff, 512, &tmp_len);
		digest["cntl"] = temp_buff;
	}
	dsarray.append(std::move(digest));
	return 0;
}

static int mime_get_digest_multi(const MIME *pmime, const char *id_string,
    size_t *poffset, Json::Value &dsarray)
{
	int count;
	size_t tmp_len;
	BOOL has_submime;
	char temp_id[64];

	if (NULL == pmime->first_boundary) {
		*poffset += 48;
	} else {
		*poffset += pmime->first_boundary - pmime->content_begin;
	}
	auto pnode = pmime->node.get_child();
	has_submime = FALSE;
	count = 1;
	while (NULL != pnode) {
		has_submime = TRUE;
		*poffset += pmime->boundary_len + 4;
		if ('\0' == id_string[0]) {
			snprintf(temp_id, 64, "%d", count);
		} else {
			snprintf(temp_id, 64, "%s.%d", id_string, count);
		}
		auto mime = static_cast<const MIME *>(pnode->pdata);
		if (mime->get_mimes_digest(temp_id, poffset, dsarray) < 0)
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
	tmp_len = pmime->content_length - (pmime->last_boundary -
	          pmime->content_begin);
	if (tmp_len > 0) {
		*poffset += tmp_len;
	} else if (0 == tmp_len) {
		*poffset += 2;
	}
	return 0;
}

static int mime_get_struct_multi(const MIME *, const char *id, size_t *ofs, size_t head_ofs, Json::Value &);

/*
 *  get the digest string of mail struct
 *  @param
 *      pmime [in]          indicate the mime object
 *      id_string[in]       id string
 *      poffset[in, out]    offset in mail
 *  @return
 *      string length in pbuff
 */
int MIME::get_structure_digest(const char *id_string, size_t *poffset,
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
		uint32_t tag_len = 0, val_len = 0;
		MEM_FILE fh = pmime->f_other_fields;
		fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (fh.read(&tag_len,
		       sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* xxxxx: yyyyy */
			fh.seek(MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
			*poffset += tag_len + 2;
			fh.read(&val_len, sizeof(uint32_t));
			fh.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
			*poffset += val_len + 2;
		}

		/* Content-Type: xxxxx */
		*poffset += 14;
		*poffset += strlen(pmime->content_type);
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		fh = pmime->f_type_params;
		fh.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (fh.read(&tag_len,
		       sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			*poffset += tag_len + 4;
			fh.seek(MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
			fh.read(&val_len, sizeof(uint32_t));
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (0 != val_len) {
				*poffset += val_len + 1;
				fh.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
			}
		}
		/* \r\n for separate head and content */
		*poffset += 4;
	}
	if (pmime->mime_type != mime_type::single)
		return mime_get_struct_multi(this, id_string, poffset,
		       head_offset, dsarray);
	if (pmime->content_begin == nullptr) {
		/* if there's nothing, just append an empty line */
		*poffset += 2;
		return 0;
	}
	if (pmime->content_length != 0) {
		*poffset += pmime->content_length;
		return 0;
	}
	auto mgl = reinterpret_cast<MAIL *>(pmime->content_begin)->get_length();
	if (mgl < 0)
		return -1;
	*poffset += mgl;
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1333: ENOMEM");
	return -1;
}

static int mime_get_struct_multi(const MIME *pmime, const char *id_string,
    size_t *poffset, size_t head_offset, Json::Value &dsarray)
{
	size_t count = 0, i, tmp_len;
	BOOL	has_submime;
	char temp_id[64], content_type[256];

	strcpy(content_type, pmime->content_type);
	if (!mime_check_ascii_printable(content_type))
		strcpy(content_type, "multipart/mixed");
	tmp_len = strlen(content_type);
	for (i = 0; i < tmp_len; i++) {
		if ('"' == content_type[i] || '\\' == content_type[i]) {
			content_type[i] = ' ';
		}
	}
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
	if (NULL == pmime->first_boundary) {
		*poffset += 48;
	} else {
		*poffset += pmime->first_boundary - pmime->content_begin;
	}
	auto pnode = pmime->node.get_child();
	has_submime = FALSE;
	count = 1;
	while (NULL != pnode) {
		has_submime = TRUE;
		*poffset += pmime->boundary_len + 4;
		if ('\0' == id_string[0]) {
			snprintf(temp_id, 64, "%zu", count);
		} else {
			snprintf(temp_id, 64, "%s.%zu", id_string, count);
		}
		if (static_cast<const MIME *>(pnode->pdata)->get_structure_digest(temp_id,
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
	tmp_len = pmime->content_length - (pmime->last_boundary -
	          pmime->content_begin);
	if (tmp_len > 0) {
		*poffset += tmp_len;
	} else if (0 == tmp_len) {
		*poffset += 2;
	}
	return 0;
}

static bool mime_parse_multiple(MIME *pmime)
{
	BOOL b_match;
	int boundary_len;
	char *ptr, *begin, *end;

#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		mlog(LV_DEBUG, "NULL pointer found in %s", __PRETTY_FUNCTION__);
		return false;
	}
#endif
	if (NULL == pmime->content_begin) {
		return false;
	}
	boundary_len = strlen(pmime->boundary_string);
	if (boundary_len <= 2) {
		return false;
	}
	begin = strchr(pmime->boundary_string, '"');
	if (NULL != begin) {
		end = strchr(begin + 1, '"');
		if (NULL == end) {
			return false;
		}
		boundary_len = end - begin - 1;
		memmove(pmime->boundary_string, begin + 1, boundary_len);
		pmime->boundary_string[boundary_len] = '\0';
	} 
	pmime->boundary_len = boundary_len;
	
	begin = pmime->content_begin;
	end = begin + pmime->content_length - boundary_len;
	for (ptr=begin; ptr < end; ptr++) {
		if (ptr[0] != '-' || ptr[1] != '-' ||
		    strncmp(pmime->boundary_string, ptr + 2, boundary_len) != 0)
			continue;
		auto nl_len = newline_size(&ptr[boundary_len+2], 2);
		if (nl_len > 0)
			break;
	}
	if (ptr == end) {
		return false;
	}	
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
	int depth = pmime->node.get_depth();
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

static bool mime_check_ascii_printable(const char *astring)
{
	return std::all_of(astring, astring + strlen(astring),
	       [&](uint8_t c) { return c >= 0x20 && c <= 0x7E; });
}

MIME *MIME::get_child()
{
	auto pmime = this;
	auto pnode = pmime->node.get_child();
	return pnode != nullptr ? static_cast<MIME *>(pnode->pdata) : nullptr;
}

MIME *MIME::get_parent()
{
	auto pmime = this;
	auto pnode = pmime->node.get_parent();
	return pnode != nullptr ? static_cast<MIME *>(pnode->pdata) : nullptr;
}

MIME *MIME::get_sibling()
{
	auto pmime = this;
	auto pnode = pmime->node.get_sibling();
	return pnode != nullptr ? static_cast<MIME *>(pnode->pdata) : nullptr;
}

const MIME *MIME::get_child() const { return deconst(this)->get_child(); }
const MIME *MIME::get_parent() const { return deconst(this)->get_parent(); }
const MIME *MIME::get_sibling() const { return deconst(this)->get_sibling(); }
