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
#include <libHX/string.h>
#include <gromox/fileio.h>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mime.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>

using namespace gromox;

static BOOL mime_parse_multiple(MIME *pmime);

static void mime_produce_boundary(MIME *pmime);

static BOOL mime_check_ascii_printable(const char *astring);

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
		debug_info("[mime]: NULL pointer found in mime_init");
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

	if (pmime->mime_type == mime_type::single) {
		if (pmime->content_touched && NULL != pmime->content_begin) {
			if (0 != pmime->content_length) {
				free(pmime->content_begin);
			}
		}
	} else if (pmime->mime_type == mime_type::multiple) {
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
BOOL MIME::retrieve(MIME *pmime_parent, char *in_buff, size_t length)
{
	auto pmime = this;
	size_t current_offset = 0;
	MIME_FIELD mime_field;

#ifdef _DEBUG_UMTA
	if (in_buff == nullptr) {
		debug_info("[mime]: NULL pointer found in MIME::retrieve");
		return FALSE;
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
		return TRUE;
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
			if (12 == mime_field.field_name_len &&
				0 == strncasecmp("Content-Type", mime_field.field_name, 12)) {
				parse_field_value(mime_field.field_value,
						mime_field.field_value_len, pmime->content_type, 256,
						&pmime->f_type_params);
				pmime->mime_type = strncasecmp(pmime->content_type, "multipart/", 10) == 0 ?
				                   mime_type::multiple : mime_type::single;
			} else {
				static_assert(sizeof(mime_field.field_name_len) == sizeof(uint32_t));
				static_assert(sizeof(mime_field.field_value_len) == sizeof(uint32_t));
				pmime->f_other_fields.write(&mime_field.field_name_len, sizeof(mime_field.field_name_len));
				pmime->f_other_fields.write(mime_field.field_name, mime_field.field_name_len);
				pmime->f_other_fields.write(&mime_field.field_value_len, sizeof(mime_field.field_value_len));
				pmime->f_other_fields.write(mime_field.field_value, mime_field.field_value_len);
			}
			if ('\r' != in_buff[current_offset])
				continue;
			pmime->head_begin = in_buff;
			pmime->head_length = current_offset;
			/*
			 * if a empty line is meet, end of mail head parse
			 * skip the empty line, which separate the head and
			 * content \r\n
			 */
			current_offset += 2;
			if (current_offset > length) {
				pmime->clear();
				return FALSE;
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
			return TRUE;
		}
		if (0 == current_offset) {
			pmime->head_touched = TRUE;
			pmime->content_begin = in_buff;
			pmime->content_length = length;
			/* old simplest unix style mail */
			strcpy(pmime->content_type, "text/plain");
			pmime->mime_type = mime_type::single;
			return TRUE;
		}
		pmime->head_begin = in_buff;
		pmime->head_length = current_offset;
		/*
		 * there's not empty line, which separate the head and
		 * content \r\n
		 */
		if (current_offset > length) {
			pmime->clear();
			return FALSE;
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
		return TRUE;
	}
	pmime->clear();
	return FALSE;
}

void MIME::clear()
{
	auto pmime = this;
	if (pmime->mime_type == mime_type::single && pmime->content_touched &&
	    pmime->content_begin != nullptr) {
		if (0 != pmime->content_length) {
			free(pmime->content_begin);
		}
		pmime->content_begin = NULL;
		pmime->content_length = 0;
	}
	pmime->mime_type = mime_type::none;
	pmime->content_type[0]	 = '\0';
	pmime->boundary_string[0]= '\0';
	pmime->boundary_len		 = 0;
	pmime->head_touched		 = FALSE;
	pmime->content_touched	 = FALSE;
	pmime->head_begin		 = NULL;
	pmime->head_length		 = 0;
	pmime->content_begin	 = NULL;
	pmime->content_length	 = 0;
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
BOOL MIME::write_content(const char *pcontent, size_t length,
    enum mime_encoding encoding_type) try
{
	auto pmime = this;
	size_t i, j;
	/* align the buffer with 64K */
	
#ifdef _DEBUG_UMTA
	if (pcontent == nullptr && length != 0) {
		debug_info("[mime]: NULL pointer found in MIME::write_content");
		return FALSE;
	}
#endif
	if (pmime->mime_type != mime_type::single)
		return FALSE;
	if (encoding_type != mime_encoding::base64 &&
	    encoding_type != mime_encoding::qp &&
	    encoding_type != mime_encoding::none) {
		debug_info("[mime]: encoding type should be one of "
			"mime_encoding::none, mime_encoding::base64, mime_encoding::qp");
		return FALSE;
	}
	if (pmime->content_touched && pmime->content_begin != nullptr &&
	    pmime->content_length != 0)
		free(pmime->content_begin);
	pmime->content_begin = NULL;
	pmime->content_length = 0;
	pmime->content_touched = TRUE;
	pmime->remove_field("Content-Transfer-Encoding");
	if (0 == length) {
		pmime->set_field("Content-Transfer-Encoding",
			encoding_type == mime_encoding::qp ?
			"quoted-printable" : "base64");
		return TRUE;
	}
	switch (encoding_type) {
	case mime_encoding::none: {
		/* should add '\r\n' at the end of buffer if it misses */
		bool added_crlf = pcontent[length-1] != '\n';
		size_t buff_length = strange_roundup(2 * length, 64 * 1024);
		pmime->content_begin = me_alloc<char>(buff_length);
		if (NULL == pmime->content_begin) {
			return FALSE;
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
		return TRUE;
	}
	case mime_encoding::qp: {
		size_t buff_length = strange_roundup(4 * length, 64 * 1024);
		auto pbuff = std::make_unique<char[]>(buff_length);
		pmime->content_begin = me_alloc<char>(buff_length);
		if (NULL == pmime->content_begin) {
			return FALSE;
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
		return TRUE;
	}
	case mime_encoding::base64: {
		size_t buff_length = strange_roundup(2 * length, 64 * 1024);
		pmime->content_begin = me_alloc<char>(buff_length);
		if (NULL == pmime->content_begin) {
			return FALSE;
		}
		encode64_ex(pcontent, length, pmime->content_begin, buff_length,
				&pmime->content_length);
		pmime->set_field("Content-Transfer-Encoding", "base64");
		return TRUE;
	}
	default:
		break;
	}
	return false;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1966: ENOMEM\n");
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
BOOL MIME::write_mail(MAIL *pmail)
{
	auto pmime = this;
#ifdef _DEBUG_UMTA
	if (pmail == nullptr) {
		debug_info("[mime]: NULL pointer found in MIME::write_mail");
        return FALSE;
    }
#endif
	if (pmime->mime_type != mime_type::single)
		return FALSE;
	if (pmime->content_touched && pmime->content_begin != nullptr) {
		if (0 != pmime->content_length) {
			free(pmime->content_begin);
		}
        pmime->content_begin = NULL;
		pmime->content_length = 0;
    }
	/* content_begin is not NULL and content_length is 0 means mail object */
	pmime->content_begin = reinterpret_cast<char *>(pmail);
	pmime->content_length = 0;
	pmime->content_touched = TRUE;
	pmime->set_field("Content-Transfer-Encoding", "8bit");
	return TRUE;
}

/*
 *	set the content type of the MIME object
 *	@param
 *		pmime [in,out]		indicate the MIME object
 *		content_type [in]	buffer containing content type
 */
BOOL MIME::set_content_type(const char *newtype)
{
	auto pmime = this;
	BOOL b_multiple;

#ifdef _DEBUG_UMTA
	if (newtype == nullptr) {
		debug_info("[mime]: NULL pointer found in mime_set_content_type");
		return FALSE;
	}
#endif
	
	b_multiple = FALSE;
	if (strncasecmp(newtype, "multipart/", 10) == 0)
		b_multiple = TRUE;
	if (pmime->mime_type == mime_type::single) {
		if (b_multiple)
			return FALSE;
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
	return TRUE;
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
BOOL MIME::enum_field(MIME_FIELD_ENUM enum_func, void *pparam)
{
	auto pmime = this;
	int	tag_len, val_len;
	char tmp_tag[MIME_NAME_LEN];
	char tmp_value[MIME_FIELD_LEN];
	
	if (!enum_func("Content-Type", pmime->content_type, pparam))
		return FALSE;
	pmime->f_other_fields.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (pmime->f_other_fields.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		pmime->f_other_fields.read(tmp_tag, tag_len);
		tmp_tag[tag_len] = '\0';
		pmime->f_other_fields.read(&val_len, sizeof(uint32_t));
		pmime->f_other_fields.read(tmp_value, val_len);
		tmp_value[val_len] = '\0';
		if (!enum_func(tmp_tag, tmp_value, pparam))
			return FALSE;
	}
	return TRUE;
}

static BOOL mime_get_content_type_field(MIME *pmime, char *value, int length)
{
	int offset;
	int tag_len;
	int val_len;
	char tmp_buff[MIME_FIELD_LEN];
	
	offset = strlen(pmime->content_type);
	if (offset >= length) {
		return FALSE;
	}
	memcpy(value, pmime->content_type, offset);
	pmime->f_type_params.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (pmime->f_type_params.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		/* content-type: xxxxx"; "yyyyy */
		if (offset + 4 + tag_len >= length) {
			return FALSE;
		}
		memcpy(value + offset, "; ", 2);
		offset += 2;
		pmime->f_type_params.read(tmp_buff, tag_len);
		memcpy(value + offset, tmp_buff, tag_len);
		offset += tag_len;
		pmime->f_type_params.read(&val_len, sizeof(uint32_t));
		pmime->f_type_params.read(tmp_buff, val_len);
		/* content_type: xxxxx; yyyyy=zzz */
		if (0 != val_len) {
			if (offset + val_len + 1 >= length) {
				return FALSE;
			}
			value[offset] = '=';
			offset ++;
			memcpy(value + offset, tmp_buff, val_len);
			offset += val_len;
		}
	}
	value[offset] = '\0';
	return TRUE;
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
BOOL MIME::get_field(const char *tag, char *value, int length)
{
	auto pmime = this;
	int tag_len, val_len;
	char tmp_buff[MIME_NAME_LEN];
	
#ifdef _DEBUG_UMTA
	if (tag == nullptr || value == nullptr) {
		debug_info("[mime]: NULL pointer found in MIME::get_field");
		return FALSE;
	}
#endif
	if (0 == strcasecmp(tag, "Content-Type")) {
		return mime_get_content_type_field(pmime, value, length);
	}
	pmime->f_other_fields.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (pmime->f_other_fields.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		pmime->f_other_fields.read(tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		pmime->f_other_fields.read(&val_len, sizeof(uint32_t));
		if (0 == strcasecmp(tag, tmp_buff)) {
			length = (length > val_len)?val_len:(length - 1);
			pmime->f_other_fields.read(value, length);
			value[length] = '\0';
			return TRUE;
		} 
		pmime->f_other_fields.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
	}
	return FALSE;
}

/*
 *	get the field number in MIME head
 *	@param
 *		pmime [in]			indicate the MIME object
 *		tag [in]			tag string
 *	@return
 *		number of same tags "XXX"
 */
int MIME::get_field_num(const char *tag)
{
	auto pmime = this;
	int i;
	int	tag_len, val_len;
	char tmp_buff[MIME_NAME_LEN];

#ifdef _DEBUG_UMTA
	if (tag == nullptr) {
		debug_info("[mime]: NULL pointer found in MIME::get_field_num");
		return 0;
	}
#endif
	if (0 == strcasecmp(tag, "Content-Type")) {
		return 1;
	}
	i = 0;
	pmime->f_other_fields.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (pmime->f_other_fields.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		pmime->f_other_fields.read(tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		pmime->f_other_fields.read(&val_len, sizeof(uint32_t));
		if (0 == strcasecmp(tag, tmp_buff)) {
			i ++;
		}
		pmime->f_other_fields.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
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
BOOL MIME::search_field(const char *tag, int order, char *value,
	int length)
{
	auto pmime = this;
	int i;
	int	tag_len, val_len;
	char tmp_buff[MIME_FIELD_LEN];
	
#ifdef _DEBUG_UMTA
	if (tag == nullptr || value == nullptr) {
		debug_info("[mime]: NULL pointer found in MIME::search_field");
		return FALSE;
	}
#endif
	if (order < 0) {
		return FALSE;
	}
	if (0 == strcasecmp(tag, "Content-Type")) {
		if (0 == order) {
			strncpy(value, pmime->content_type, length - 1);
			value[length - 1] = '\0';
		} else {
			return FALSE;
		}
	}
	i = -1;
	pmime->f_other_fields.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (pmime->f_other_fields.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		pmime->f_other_fields.read(tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		pmime->f_other_fields.read(&val_len, sizeof(uint32_t));
		if (0 == strcasecmp(tag, tmp_buff)) {
			i ++;
			if (i == order) {
				length = (length > val_len)?val_len:(length - 1);
				pmime->f_other_fields.read(value, length);
				value[length] = '\0';
				return TRUE;
			}
		} 
		pmime->f_other_fields.read(tmp_buff, val_len);
	}
	return FALSE;
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
BOOL MIME::set_field(const char *tag, const char *value)
{
	auto pmime = this;
	MEM_FILE file_tmp;
	int		tag_len, val_len;
	char	tmp_buff[MIME_FIELD_LEN];
	BOOL	found_tag = FALSE;
	int		i, mark;
	
#ifdef _DEBUG_UMTA
	if (tag == nullptr || value == nullptr) {
		debug_info("[mime]: NULL pointer found in MIME::set_field");
		return FALSE;
	}
#endif
	if (0 == strcasecmp(tag, "Content-Type")) {
		pmime->f_type_params.clear();
		parse_field_value(value, strlen(value), tmp_buff, 256,
			&pmime->f_type_params);
		if (!pmime->set_content_type(tmp_buff)) {
			pmime->f_type_params.clear();
			return FALSE;
		}
		return TRUE;
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
	return TRUE;
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
BOOL MIME::append_field(const char *tag, const char *value)
{
	auto pmime = this;
	int	tag_len, val_len;
	
#ifdef _DEBUG_UMTA
	if (tag == nullptr || value == nullptr) {
		debug_info("[mime]: NULL pointer found in MIME::append_field");
		return FALSE;
	}
#endif
	if (0 == strcasecmp(tag, "Content-Type")) {
		return FALSE;
	}
	tag_len = strlen(tag);
	val_len = strlen(value);
	pmime->f_other_fields.write(&tag_len, sizeof(uint32_t));
	pmime->f_other_fields.write(tag, tag_len);
	pmime->f_other_fields.write(&val_len, sizeof(uint32_t));
	pmime->f_other_fields.write(value, val_len);
	pmime->head_touched = TRUE;
	return TRUE;
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
BOOL MIME::remove_field(const char *tag)
{
	auto pmime = this;
	BOOL found_tag = false;
	MEM_FILE file_tmp;
	char tmp_buff[MIME_FIELD_LEN];
	int tag_len, val_len;

	if (0 == strcasecmp(tag, "Content-Type")) {
		return FALSE;
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
BOOL MIME::get_content_param(const char *tag, char *value,
	int length)
{
	auto pmime = this;
	int	tag_len, val_len;
	char	tmp_buff[MIME_FIELD_LEN];
	int		distance;
	
#ifdef _DEBUG_UMTA
	if (tag == nullptr || value == nullptr) {
		debug_info("[mime]: NULL pointer found in MIME::get_content_param");
		return FALSE;
	}
#endif
	pmime->f_type_params.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (pmime->f_type_params.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		pmime->f_type_params.read(tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		if (0 == strcasecmp(tag, tmp_buff)) {
			pmime->f_type_params.read(&val_len, sizeof(uint32_t));
			distance = (val_len > length - 1)?(length - 1):val_len;
			pmime->f_type_params.read(value, distance);
			value[distance] = '\0';
			return TRUE;
		} 
		pmime->f_type_params.read(&val_len, sizeof(uint32_t));
		pmime->f_type_params.read(tmp_buff, val_len);
	}
	return FALSE;
}

/*
 *	set the param of content type
 *	@param
 *		pmime [in,out]		indicate MIME object
 *		tag [in]			tag string
 *		value [in]			value string
 */
BOOL MIME::set_content_param(const char *tag, const char *value)
{
	auto pmime = this;
	MEM_FILE file_tmp;
	int	tag_len, val_len;
	char	tmp_buff[MIME_FIELD_LEN];
	BOOL	found_tag = FALSE;
	int i, mark;
	
#ifdef _DEBUG_UMTA
	if (tag == nullptr || value == nullptr) {
		debug_info("[mime]: NULL pointer found in MIME::set_content_param");
		return FALSE;
	}
#endif
	if (0 == strcasecmp(tag, "boundary")) {
		auto bdlen = strlen(value);
		if (bdlen > VALUE_LEN - 3 || bdlen < 3)
			return FALSE;
		if ('"' == value[0]) {
			if (value[bdlen-1] != '"')
				return FALSE;
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
		return TRUE;
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
	return TRUE;
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
BOOL MIME::serialize(STREAM *pstream)
{
	auto pmime = this;
	int		tag_len, val_len;
	long	len, tmp_len;
	char	tmp_buff[MIME_FIELD_LEN];
	MIME	*pmime_child;
	BOOL	has_submime;
	
#ifdef _DEBUG_UMTA
	if (pstream == nullptr) {
		debug_info("[mime]: NULL pointer found in MIME::serialize");
		return FALSE;
	}
#endif
	if (pmime->mime_type == mime_type::none)
		return FALSE;
	if (!pmime->head_touched) {
		/* the original buffer contains \r\n */
		if (pmime->head_begin + pmime->head_length + 2 == pmime->content_begin){
			pstream->write(pmime->head_begin, pmime->head_length + 2);
		} else {
			pstream->write(pmime->head_begin, pmime->head_length);
			pstream->write("\r\n", 2);
		}
	} else {	
		pmime->f_other_fields.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (pmime->f_other_fields.read(&tag_len,
		       sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* xxxxx: yyyyy */
			pmime->f_other_fields.read(tmp_buff, tag_len);
			pstream->write(tmp_buff, tag_len);
			pstream->write(": ", 2);
			pmime->f_other_fields.read(&val_len, sizeof(uint32_t));
			pmime->f_other_fields.read(tmp_buff, val_len);
			pstream->write(tmp_buff, val_len);
			/* \r\n */
			pstream->write("\r\n", 2);
		}

		/* Content-Type: xxxxx */
		pstream->write("Content-Type: ", 14);
		len = strlen(pmime->content_type);
		pstream->write(pmime->content_type, len);
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		pmime->f_type_params.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (pmime->f_type_params.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			pstream->write(";\r\n\t", 4);
			pmime->f_type_params.read(tmp_buff, tag_len);
			pstream->write(tmp_buff, tag_len);
			pmime->f_type_params.read(&val_len, sizeof(uint32_t));
			pmime->f_type_params.read(tmp_buff, val_len);
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
		else
			reinterpret_cast<MAIL *>(pmime->content_begin)->serialize(pstream);
		return TRUE;
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
		pmime_child = (MIME*)pnode->pdata;
		if (!pmime_child->serialize(pstream))
			return FALSE;
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
		return TRUE;
	}
	tmp_len = pmime->content_length -
	          (pmime->last_boundary - pmime->content_begin);
	if (tmp_len > 0) {
		pstream->write(pmime->last_boundary, tmp_len);
	} else if (0 == tmp_len) {
		pstream->write("\r\n", 2);
	} else {
		debug_info("[mime]: fatal error in MIME::serialize");
	}
	return TRUE;
}

static BOOL mime_read_multipart_content(MIME *pmime,
	char *out_buff, size_t *plength)
{
	void *ptr;
	size_t offset, tmp_len;
	unsigned int buff_size;
	BOOL has_submime;
	MIME *pmime_child;
	
	auto tmp_size = pmime->get_length();
	if (tmp_size < 0) {
		*plength = 0;
		return false;
	}
	alloc_limiter<stream_block> pallocator(tmp_size / STREAM_BLOCK_SIZE + 1);
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
		pmime_child = (MIME*)pnode->pdata;
		if (!pmime_child->serialize(&tmp_stream))
			return FALSE;
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
		} else {
			debug_info("[mime]: fatal error in mime_read_multipart_content");
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
	return TRUE;
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
BOOL MIME::read_head(char *out_buff, size_t *plength)
{
	auto pmime = this;
	uint32_t tag_len, val_len;
	size_t	len, offset;
	char	tmp_buff[MIME_FIELD_LEN + MIME_NAME_LEN + 4];
	
	if (pmime->mime_type == mime_type::none) {
#ifdef _DEBUG_UMTA
		debug_info("[mime]: mime content type is not set");
#endif
		return FALSE;
	}
	if (!pmime->head_touched){
		if (pmime->head_length + 2 > *plength) {
			*plength = 0;
			return FALSE;
		}
		memcpy(out_buff, pmime->head_begin, pmime->head_length);
		memcpy(out_buff + pmime->head_length, "\r\n", 2);
		*plength = pmime->head_length + 2;
		return TRUE;
	}
	offset = 0;
	pmime->f_other_fields.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (pmime->f_other_fields.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		/* xxxxx: yyyyy */
		pmime->f_other_fields.read(tmp_buff, tag_len);
		len = tag_len;
		memcpy(tmp_buff + len, ": ", 2);
		len += 2;
		pmime->f_other_fields.read(&val_len, sizeof(uint32_t));
		pmime->f_other_fields.read(tmp_buff + len, val_len);
		len += val_len;
		memcpy(tmp_buff + len, "\r\n", 2);
		len += 2;
		if (offset + len > *plength) {
			*plength = 0;
			return FALSE;
		}
		memcpy(tmp_buff + offset, tmp_buff, len);
		offset += len;
	}
	/* Content-Type: xxxxx */
	memcpy(tmp_buff, "Content-Type: ", 14);
	len = 14;
	val_len = strlen(pmime->content_type);
	memcpy(tmp_buff + len, pmime->content_type, val_len);
	len += val_len;
	/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
	pmime->f_type_params.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (pmime->f_type_params.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		/* content-type: xxxxx"; \r\n\t"yyyyy */
		if (len > MIME_FIELD_LEN + MIME_NAME_LEN - tag_len) {
			return FALSE;
		}
		memcpy(tmp_buff + len, ";\r\n\t", 4);
		len += 4;
		pmime->f_type_params.read(tmp_buff + len, tag_len);
		len += tag_len;
		pmime->f_type_params.read(&val_len, sizeof(uint32_t));
		if (len > MIME_FIELD_LEN + MIME_NAME_LEN + 3 - val_len) {
			return FALSE;
		}
		/* content_type: xxxxx; \r\n\tyyyyy=zzz */
		if (0 != val_len) {
			memcpy(tmp_buff + len, "=", 1);
			len += 1;
			pmime->f_type_params.read(tmp_buff + len, val_len);
			len += val_len;
		}
	}
	if (len > MIME_FIELD_LEN + MIME_NAME_LEN) {
		return FALSE;
	}
	/* \r\n for separate head and content */
	memcpy(tmp_buff + len, "\r\n\r\n", 4);
	len += 4;
	if (offset + len > *plength) {
		*plength = 0;
		return FALSE;
	}
	memcpy(tmp_buff + offset, tmp_buff, len);
	offset += len;
	*plength = offset;
	return TRUE;
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
BOOL MIME::read_content(char *out_buff, size_t *plength) try
{
	auto pmime = this;
	void *ptr;
	size_t i, offset, max_length;
	unsigned int buff_size;
	
#ifdef _DEBUG_UMTA
	if (out_buff == nullptr || plength == nullptr) {
		debug_info("[mime]: NULL pointer found in MIME::read_content");
		return FALSE;
	}
#endif
	max_length = *plength;
	if (max_length > 0)
		*out_buff = '\0';
	if (pmime->mime_type == mime_type::none) {
		*plength = 0;
		return FALSE;
	}
	if (pmime->mime_type == mime_type::multiple)
		return mime_read_multipart_content(pmime, out_buff, plength);
	if (*plength <= 0) {
		*plength = 0;
		return FALSE;
	}
	if (NULL == pmime->content_begin) {
		*plength = 0;
		return TRUE;
	}
	
	/* content is an email object */
	if (0 == pmime->content_length) {
		auto mail_len = reinterpret_cast<MAIL *>(pmime->content_begin)->get_length();
		if (mail_len <= 0) {
			debug_info("[mime]: Failed to get mail length in MIME::read_content");
			*plength = 0;
			return FALSE;
		}
		if (static_cast<size_t>(mail_len) >= max_length) {
			*plength = 0;
			return FALSE;
		}
		alloc_limiter<stream_block> pallocator(mail_len / STREAM_BLOCK_SIZE + 1);
		STREAM tmp_stream(&pallocator);
		if (!reinterpret_cast<MAIL *>(pmime->content_begin)->serialize(&tmp_stream)) {
			*plength = 0;
			return FALSE;
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
		return TRUE;
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
	/* \r\n before boundary string or end of mail should not be included */
	size_t tmp_len = pmime->content_length < 2 ? 1 : pmime->content_length - 2;
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
			debug_info("[mime]: fail to decode base64 mime content");
			if (0 == *plength) {
				return FALSE;
			}
		}
		return TRUE;
	case mime_encoding::qp: {
		auto qdlen = qp_decode_ex(out_buff, max_length, pbuff.get(), size);
		if (qdlen < 0) {
			goto COPY_RAW_DATA;
		} else {
			*plength = qdlen;
			return TRUE;
		}
	}
	case mime_encoding::uuencode:
		if (uudecode(pbuff.get(), size, nullptr, nullptr, 0, out_buff,
		    max_length, plength) != 0) {
			debug_info("[mime]: fail to decode uuencode mime content");
			goto COPY_RAW_DATA;
		}
		return TRUE;
	default:
 COPY_RAW_DATA:
		if (max_length >= size) {
			memcpy(out_buff, pbuff.get(), size);
			*plength = size;
			return TRUE;
		} else {
			*plength = 0;
			return FALSE;
		}
	}
} catch (const std::bad_alloc &) {
	debug_info("[mime]: E-1973: Failed to allocate memory in MIME::read_content");
	*plength = 0;
	return false;
}

/*
 *	write MIME object into file
 *	@param
 *		pmime [in]		indicate the MIME object
 *		fd				file descriptor
 *	@return
 *		TRUE			OK to copy out the MIME
 *		FALSE			buffer is too short
 */
BOOL MIME::to_file(int fd)
{
	auto pmime = this;
	BOOL has_submime;
	MIME *pmime_child;
	size_t len, tmp_len;
	int	tag_len, val_len;
	char tmp_buff[MIME_FIELD_LEN + MIME_NAME_LEN + 4];
	
	if (pmime->mime_type == mime_type::none) {
#ifdef _DEBUG_UMTA
		debug_info("[mime]: mime content type is not set");
#endif
		return FALSE;
	}
	if (!pmime->head_touched) {
		/* the original buffer contains \r\n */
		if (pmime->head_begin + pmime->head_length
			+ 2 == pmime->content_begin) {
			auto wrlen = write(fd, pmime->head_begin, pmime->head_length + 2);
			if (wrlen < 0 || static_cast<size_t>(wrlen) != pmime->head_length + 2)
				return FALSE;
		} else {
			auto wrlen = write(fd, pmime->head_begin, pmime->head_length);
			if (wrlen < 0 || static_cast<size_t>(wrlen) != pmime->head_length)
				return FALSE;
			if (2 != write(fd, "\r\n", 2)) {
				return FALSE;
			}
		}
	} else {	
		pmime->f_other_fields.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (pmime->f_other_fields.read(&tag_len,
		       sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* xxxxx: yyyyy */
			pmime->f_other_fields.read(tmp_buff, tag_len);
			len = tag_len;
			memcpy(tmp_buff + len, ": ", 2);
			len += 2;
			pmime->f_other_fields.read(&val_len, sizeof(uint32_t));
			pmime->f_other_fields.read(tmp_buff + len, val_len);
			len += val_len;
			memcpy(tmp_buff + len, "\r\n", 2);
			len += 2;
			auto wrlen = write(fd, tmp_buff, len);
			if (wrlen < 0 || static_cast<size_t>(wrlen) != len)
				return FALSE;
		}

		/* Content-Type: xxxxx */
		memcpy(tmp_buff, "Content-Type: ", 14);
		len = 14;
		val_len = strlen(pmime->content_type);
		memcpy(tmp_buff + len, pmime->content_type, val_len);
		len += val_len;
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		pmime->f_type_params.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (pmime->f_type_params.read(&tag_len,
		       sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			if (len > MIME_FIELD_LEN + MIME_NAME_LEN - tag_len) {
				return FALSE;
			}
			memcpy(tmp_buff + len, ";\r\n\t", 4);
			len += 4;
			pmime->f_type_params.read(tmp_buff + len, tag_len);
			len += tag_len;
			pmime->f_type_params.read(&val_len, sizeof(uint32_t));
			if (len > MIME_FIELD_LEN + MIME_NAME_LEN + 3 - val_len) {
				return FALSE;
			}
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (0 != val_len) {
				memcpy(tmp_buff + len, "=", 1);
				len += 1;
				pmime->f_type_params.read(tmp_buff + len, val_len);
				len += val_len;
			}
		}
		if (len > MIME_FIELD_LEN + MIME_NAME_LEN) {
			return FALSE;
		}
		/* \r\n for separate head and content */
		memcpy(tmp_buff + len, "\r\n\r\n", 4);
		len += 4;
		auto wrlen = write(fd, tmp_buff, len);
		if (wrlen < 0 || static_cast<size_t>(wrlen) != len)
			return FALSE;
	}
	if (pmime->mime_type == mime_type::single) {
		if (NULL != pmime->content_begin) {
			if (0 != pmime->content_length) {
				auto wrlen = write(fd, pmime->content_begin, pmime->content_length);
				if (wrlen < 0 || static_cast<size_t>(wrlen) != pmime->content_length)
					return FALSE;
			} else {
				if (!reinterpret_cast<MAIL *>(pmime->content_begin)->to_file(fd))
					return FALSE;
			}
		} else {
			/* if there's nothing, just append an empty line */
			if (2 != write(fd, "\r\n", 2)) {
				return FALSE;
			}
		}
		return TRUE;
	}
	if (NULL == pmime->first_boundary) {
		if (48 != write(fd, "This is a multi-part message "
		    "in MIME format.\r\n\r\n", 48)) {
			return FALSE;
		}
	} else if (write(fd, pmime->content_begin, pmime->first_boundary - pmime->content_begin) !=
	    pmime->first_boundary - pmime->content_begin) {
		return FALSE;
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
			return FALSE;
		pmime_child = (MIME*)pnode->pdata;
		if (!pmime_child->to_file(fd))
			return FALSE;
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
			return FALSE;
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
			debug_info("[mime]: E-1640");
			return FALSE;
		}
	}
	auto wrlen = write(fd, tmp_buff, len);
	if (wrlen < 0 || static_cast<size_t>(wrlen) != len)
		return FALSE;
	return TRUE;
}

/*
 *	write MIME object into ssl
 *	@param
 *		pmime [in]		indicate the MIME object
 *		ssl	[in]		SSL object
 *	@return
 *		TRUE			OK to copy out the MIME
 *		FALSE			buffer is too short
 */
BOOL MIME::to_tls(SSL *ssl)
{
	auto pmime = this;
	BOOL has_submime;
	MIME *pmime_child;
	size_t len, tmp_len;
	int tag_len, val_len;
	char tmp_buff[MIME_FIELD_LEN + MIME_NAME_LEN + 4];
	
#ifdef _DEBUG_UMTA
	if (tls == nullptr) {
		debug_info("[mime]: NULL pointer found in MIME::to_tls");
		return FALSE;
	}
#endif
	if (pmime->mime_type == mime_type::none) {
#ifdef _DEBUG_UMTA
		debug_info("[mime]: mime content type is not set");
#endif
		return FALSE;
	}
	if (!pmime->head_touched) {
		/* the original buffer contains \r\n */
		if (pmime->head_begin + pmime->head_length
			+ 2 == pmime->content_begin) {
			auto wrlen = SSL_write(ssl, pmime->head_begin, pmime->head_length + 2);
			if (wrlen < 0 || static_cast<size_t>(wrlen))
				return FALSE;
		} else {
			auto wrlen = SSL_write(ssl, pmime->head_begin, pmime->head_length);
			if (wrlen < 0 || static_cast<size_t>(wrlen) != pmime->head_length)
				return FALSE;
			if (2 != SSL_write(ssl, "\r\n", 2)) {
				return FALSE;
			}
		}
	} else {	
		pmime->f_other_fields.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (pmime->f_other_fields.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* xxxxx: yyyyy */
			pmime->f_other_fields.read(tmp_buff, tag_len);
			len = tag_len;
			memcpy(tmp_buff + len, ": ", 2);
			len += 2;
			pmime->f_other_fields.read(&val_len, sizeof(uint32_t));
			pmime->f_other_fields.read(tmp_buff + len, val_len);
			len += val_len;
			memcpy(tmp_buff + len, "\r\n", 2);
			len += 2;
			auto wrlen = SSL_write(ssl, tmp_buff, len);
			if (wrlen < 0 || static_cast<size_t>(wrlen) != len)
				return FALSE;
		}

		/* Content-Type: xxxxx */
		memcpy(tmp_buff, "Content-Type: ", 14);
		len = 14;
		val_len = strlen(pmime->content_type);
		memcpy(tmp_buff + len, pmime->content_type, val_len);
		len += val_len;
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		pmime->f_type_params.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (pmime->f_type_params.read(&tag_len,
		       sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			if (len > MIME_FIELD_LEN + MIME_NAME_LEN - tag_len) {
				return FALSE;
			}
			memcpy(tmp_buff + len, ";\r\n\t", 4);
			len += 4;
			pmime->f_type_params.read(tmp_buff + len, tag_len);
			len += tag_len;
			pmime->f_type_params.read(&val_len, sizeof(uint32_t));
			if (len > MIME_FIELD_LEN + MIME_NAME_LEN + 3 - val_len) {
				return FALSE;
			}
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (0 != val_len) {
				memcpy(tmp_buff + len, "=", 1);
				len += 1;
				pmime->f_type_params.read(tmp_buff + len, val_len);
				len += val_len;
			}
		}
		if (len > MIME_FIELD_LEN + MIME_NAME_LEN) {
			return FALSE;
		}
		/* \r\n for separate head and content */
		memcpy(tmp_buff + len, "\r\n\r\n", 4);
		len += 4;
		auto wrlen = SSL_write(ssl, tmp_buff, len);
		if (wrlen < 0 || static_cast<size_t>(wrlen) != len)
			return FALSE;
	}
	if (pmime->mime_type == mime_type::single) {
		if (NULL != pmime->content_begin) {
			if (0 != pmime->content_length) {
				auto wrlen = SSL_write(ssl, pmime->content_begin, pmime->content_length);
				if (wrlen < 0 || static_cast<size_t>(wrlen) != pmime->content_length)
					return FALSE;
			} else {
				if (!reinterpret_cast<MAIL *>(pmime->content_begin)->to_ssl(ssl))
					return FALSE;
			}
		} else {
			/* if there's nothing, just append an empty line */
			if (2 != SSL_write(ssl, "\r\n", 2)) {
				return FALSE;
			}
		}
		return TRUE;
	}
	if (NULL == pmime->first_boundary) {
		if (48 != SSL_write(ssl, "This is a multi-part message "
		    "in MIME format.\r\n\r\n", 48)) {
			return FALSE;
		}
	} else if (SSL_write(ssl, pmime->content_begin, pmime->first_boundary - pmime->content_begin) !=
	    pmime->first_boundary - pmime->content_begin) {
		return FALSE;
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
		auto wrlen = SSL_write(ssl, tmp_buff, len);
		if (wrlen < 0 || static_cast<size_t>(wrlen) != len)
			return FALSE;
		pmime_child = (MIME*)pnode->pdata;
		if (!pmime_child->to_tls(ssl))
			return FALSE;
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
		auto wrlen = SSL_write(ssl, tmp_buff, len);
		if (wrlen < 0 || static_cast<size_t>(wrlen) != len)
			return FALSE;
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
			debug_info("[mime]: E-1641");
			return FALSE;
		}
	}
	auto wrlen = SSL_write(ssl, tmp_buff, len);
	if (wrlen < 0 || static_cast<size_t>(wrlen) != len)
		return FALSE;
	return TRUE;
}

/*
 *	check dot-stuffing in MIME object
 *	@param
 *		pmime [in]		indicate the MIME object
 *	@return
 *		TRUE			dot-stuffing in MIME
 *		FALSE			no dot-stuffing in MIME
 */
BOOL MIME::check_dot()
{
	auto pmime = this;
	size_t	tmp_len;
	int		tag_len, val_len;
	char	tmp_buff[MIME_FIELD_LEN + MIME_NAME_LEN + 4];
	MIME	*pmime_child;
	
	if (pmime->mime_type == mime_type::none) {
#ifdef _DEBUG_UMTA
		debug_info("[mime]: mime content type is not set");
#endif
		return FALSE;
	}
	if (!pmime->head_touched) {
		if (pmime->head_length >= 2 && (('.' == pmime->head_begin[0] &&
			'.' == pmime->head_begin[1]) || NULL != memmem(
			pmime->head_begin, pmime->head_length, "\r\n..", 4))) {
			return TRUE;
		}
	} else {	
		pmime->f_other_fields.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (pmime->f_other_fields.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* xxxxx: yyyyy */
			pmime->f_other_fields.read(tmp_buff, tag_len);
			if (tag_len >= 2 && '.' == tmp_buff[0] && '.' == tmp_buff[1]) {
				return TRUE;
			}
			pmime->f_other_fields.read(&val_len, sizeof(uint32_t));
			pmime->f_other_fields.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
		}
		
	}
	if (pmime->mime_type == mime_type::single) {
		if (NULL != pmime->content_begin) {
			if (0 != pmime->content_length) {
				if (pmime->content_length >= 2 &&
					(('.' == pmime->content_begin[0] &&
					'.' == pmime->content_begin[1]) ||
					NULL != memmem(pmime->content_begin,
					pmime->content_length, "\r\n..", 4))) {
					return TRUE;
				}
			} else if (reinterpret_cast<MAIL *>(pmime->content_begin)->check_dot()) {
				return TRUE;
			}
		} 
		return TRUE;
	}
	if (NULL != pmime->first_boundary) {
		tmp_len = pmime->first_boundary - pmime->content_begin;
		if (tmp_len >= 2 && (('.' == pmime->first_boundary[0] &&
		    '.' == pmime->first_boundary[1]) ||
		    NULL != memmem(pmime->first_boundary, tmp_len, "\r\n..", 4))) {
			return TRUE;
		}
	}
	auto pnode = pmime->node.get_child();
	while (NULL != pnode) {
		pmime_child = (MIME *)pnode->pdata;
		if (pmime_child->check_dot())
			return TRUE;
		pnode = pnode->get_sibling();
	}
	if (NULL != pmime->last_boundary) {
		tmp_len = pmime->content_length -
		          (pmime->last_boundary - pmime->content_begin);
		if (tmp_len >= 2 && (('.' == pmime->last_boundary[0] &&
		    '.' == pmime->last_boundary[1]) ||
		    NULL != memmem(pmime->last_boundary, tmp_len, "\r\n..", 4))) {
			return TRUE;
		}
	}
	return FALSE;
}

/*
 *	calculate MIME length in bytes
 *	@param
 *		pmime [in]		indicate the MIME object
 *	@return
 *		length of mime object
 */
ssize_t MIME::get_length()
{
	auto pmime = this;
	int		tag_len, val_len;
	MIME	*pmime_child;
	BOOL	has_submime;
	
	if (pmime->mime_type == mime_type::none)
		return -1;
	size_t mime_len = 0;
	if (!pmime->head_touched) {
		/* the original buffer contains \r\n */
		mime_len += pmime->head_length + 2;
	} else {	
		pmime->f_other_fields.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (pmime->f_other_fields.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* xxxxx: yyyyy */
			pmime->f_other_fields.seek(MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
			mime_len += tag_len + 2;
			pmime->f_other_fields.read(&val_len, sizeof(uint32_t));
			pmime->f_other_fields.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
			mime_len += val_len + 2;
		}

		/* Content-Type: xxxxx */
		mime_len += 14;
		mime_len += strlen(pmime->content_type);
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		pmime->f_type_params.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (pmime->f_type_params.read(&tag_len,
		       sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			mime_len += tag_len + 4;
			pmime->f_type_params.seek(MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
			pmime->f_type_params.read(&val_len, sizeof(uint32_t));
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (0 != val_len) {
				mime_len += val_len + 1;
				pmime->f_type_params.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
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
		return mime_len;
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
		pmime_child = (MIME*)pnode->pdata;
		auto mgl = pmime_child->get_length();
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
	return mime_len;
}

BOOL MIME::get_filename(char *file_name)
{
	auto pmime = this;
	int i;
	int mode;
	char *ptr;
	char *pend;
	int tmp_len;
	char *pbegin;
	char encoding[256];
	
	if (pmime->get_content_param("name", file_name, 256)) {
		goto FIND_FILENAME;
	} else if (pmime->get_field("Content-Disposition", file_name, 256)) {
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
		return FALSE;
	} else if (pmime->get_field("Content-Transfer-Encoding", encoding, 256)) {
		if (0 == strcasecmp(encoding, "uue") ||
			0 == strcasecmp(encoding, "x-uue") ||
			0 == strcasecmp(encoding, "uuencode") ||
			0 == strcasecmp(encoding, "x-uuencode")) {
			if (0 == pmime->content_length) {
				return FALSE;
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
				return FALSE;
			}
			ptr += 6;
			if (' ' != ptr[3]) {
				return FALSE;
			}
			if (1 != sscanf(ptr, "%o ", &mode)) {
				return FALSE;
			}
			ptr += 4;
			for (i=0; i<256; i++,ptr++) {
				if ('\r' == *ptr || '\n' == *ptr) {
					ptr ++;
					file_name[i] = '\0';
					goto FIND_FILENAME;
				}
				file_name[i] = *ptr;
			}
		}
	}
	return FALSE;
	
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
		return FALSE;
	}
	return TRUE;
}

static ssize_t mime_get_digest_single(MIME *, const char *id, size_t *ofs, size_t head_ofs, size_t *cnt, char *buf, size_t len);
static ssize_t mime_get_digest_mul(MIME *, const char *id, size_t *ofs, size_t *cnt, char *buf, size_t len);

/*
 *  get the digest string of mail mime
 *  @param
 *      pmime [in]          indicate the mime object
 *      id_string[in]       id string
 *      poffset[in, out]    offset in mail
 *      pcount[in, out]     count of mime in mail
 *      pbuff [out]         for retrieving the digest
 *      length              maximum length of buffer
 *  @return
 *      string length in pbuff
 */
ssize_t MIME::get_mimes_digest(const char *id_string,
    size_t *poffset, size_t *pcount, char *pbuff, size_t length)
{
	auto pmime = this;
#ifdef _DEBUG_UMTA
	if (pbuff == nullptr || poffset == nullptr || pcount == nullptr) {
		debug_info("[mime]: NULL pointer found in MIME::get_mimes_digest");
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
		pmime->f_other_fields.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (pmime->f_other_fields.read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* xxxxx: yyyyy */
			pmime->f_other_fields.seek(MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
			*poffset += tag_len + 2;
			pmime->f_other_fields.read(&val_len, sizeof(uint32_t));
			pmime->f_other_fields.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
			*poffset += val_len + 2;
		}

		/* Content-Type: xxxxx */
		*poffset += 14;
		*poffset += strlen(pmime->content_type);
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		pmime->f_type_params.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (pmime->f_type_params.read(&tag_len,
		       sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			*poffset += tag_len + 4;
			pmime->f_type_params.seek(MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
			pmime->f_type_params.read(&val_len, sizeof(uint32_t));
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (0 != val_len) {
				*poffset += val_len + 1;
				pmime->f_type_params.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
			}
		}
		/* \r\n for separate head and content */
		*poffset += 4;
	}
	if (pmime->mime_type == mime_type::single)
		return mime_get_digest_single(this, id_string, poffset,
		       head_offset, pcount, pbuff, length);
	return mime_get_digest_mul(this, id_string, poffset, pcount,
	       pbuff, length);
}

static ssize_t mime_get_digest_single(MIME *pmime, const char *id_string,
    size_t *poffset, size_t head_offset, size_t *pcount, char *pbuff,
    size_t length)
{
	size_t i, content_len, buff_len = 0, tmp_len;
	char charset_buff[32], content_type[256], encoding_buff[128];
	char file_name[256], temp_buff[512], content_ID[128];
	char content_location[256], content_disposition[256], *ptoken;

	if (*pcount > 0) {
		pbuff[buff_len] = ',';
		buff_len ++;
	}
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

	if (!pmime->get_field("Content-Transfer-Encoding", encoding_buff, 128) ||
	    !mime_check_ascii_printable(encoding_buff)) {
		buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
		            "{\"id\":\"%s\",\"ctype\":\"%s\","
		            "\"encoding\":\"8bit\",\"head\":%zu,\"begin\":%zu,",
		            id_string, content_type, head_offset, *poffset);
	} else {
		tmp_len = strlen(encoding_buff);
		for (i = 0; i < tmp_len; i++) {
			if ('"' == encoding_buff[i] || '\\' == encoding_buff[i]) {
				encoding_buff[i] = ' ';
			}
		}
		HX_strrtrim(encoding_buff);
		HX_strltrim(encoding_buff);
		buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
		            "{\"id\":\"%s\",\"ctype\":\"%s\","
		            "\"encoding\":\"%s\",\"head\":%zu,\"begin\":%zu,",
		            id_string, content_type, encoding_buff, head_offset,
		            *poffset);
	}

	if (buff_len >= length - 1) {
		return -1;
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

	*pcount += 1;
	buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
	            "\"length\":%zu", content_len);
	if (buff_len >= length - 1) {
		return -1;
	}

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
		buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
		            ",\"charset\":\"%s\"", charset_buff);
		if (buff_len >= length - 1) {
			return -1;
		}
	}

	if (pmime->get_filename(file_name)) {
		encode64(file_name, strlen(file_name), temp_buff, 512, &tmp_len);
		buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
		            ",\"filename\":\"%s\"", temp_buff);
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
			buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
			            ",\"cntdspn\":\"%s\"", content_disposition);
		}
	}

	if (buff_len >= length - 1) {
		return -1;
	}
	if (pmime->get_field("Content-ID", content_ID, 128)) {
		tmp_len = strlen(content_ID);
		encode64(content_ID, tmp_len, temp_buff, 256, &tmp_len);
		buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
		            ",\"cid\":\"%s\"", temp_buff);
		if (buff_len >= length - 1) {
			return -1;
		}
	}
	if (pmime->get_field("Content-Location", content_location, 256)) {
		tmp_len = strlen(content_location);
		encode64(content_location, tmp_len, temp_buff, 512, &tmp_len);
		buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
		            ",\"cntl\":\"%s\"", temp_buff);
		if (buff_len >= length - 1) {
			return -1;
		}
	}

	pbuff[buff_len] = '}';
	buff_len++;
	return buff_len;
}

static ssize_t mime_get_digest_mul(MIME *pmime, const char *id_string,
    size_t *poffset, size_t *pcount, char *pbuff, size_t length)
{
	int count;
	size_t buff_len = 0, tmp_len;
	MIME *pmime_child;
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
		pmime_child = (MIME *)pnode->pdata;
		if ('\0' == id_string[0]) {
			snprintf(temp_id, 64, "%d", count);
		} else {
			snprintf(temp_id, 64, "%s.%d", id_string, count);
		}
		auto gmd = pmime_child->get_mimes_digest(temp_id, poffset,
		           pcount, pbuff + buff_len, length - buff_len);
		if (gmd < 0 || buff_len + gmd >= length - 1) {
			return -1;
		}
		buff_len += gmd;
		pnode = pnode->get_sibling();
		count++;
	}
	if (!has_submime)
		*poffset += pmime->boundary_len + 6;
	*poffset += pmime->boundary_len + 4;
	if (NULL == pmime->last_boundary) {
		*poffset += 4;
	} else {
		tmp_len = pmime->content_length - (pmime->last_boundary -
		          pmime->content_begin);
		if (tmp_len > 0) {
			*poffset += tmp_len;
		} else if (0 == tmp_len) {
			*poffset += 2;
		}
	}
	return buff_len;
}

static ssize_t mime_get_struct_mul(MIME *, const char *id, size_t *ofs, size_t head_ofs, size_t *cnt, char *buf, size_t len);

/*
 *  get the digest string of mail struct
 *  @param
 *      pmime [in]          indicate the mime object
 *      id_string[in]       id string
 *      poffset[in, out]    offset in mail
 *      pcount[in, out]     count of mime in mail
 *      pbuff [out]         for retrieving the digest
 *      length              maximum length of buffer
 *  @return
 *      string length in pbuff
 */
ssize_t MIME::get_structure_digest(const char *id_string,
    size_t *poffset, size_t *pcount, char *pbuff, size_t length)
{
	auto pmime = this;
#ifdef _DEBUG_UMTA
	if (pbuff == nullptr || poffset == nullptr || pcount == nulllptr) {
		debug_info("[mime]: NULL pointer found in MIME::get_structure_digest");
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
		pmime->f_other_fields.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (pmime->f_other_fields.read(&tag_len,
		       sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* xxxxx: yyyyy */
			pmime->f_other_fields.seek(MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
			*poffset += tag_len + 2;
			pmime->f_other_fields.read(&val_len, sizeof(uint32_t));
			pmime->f_other_fields.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
			*poffset += val_len + 2;
		}

		/* Content-Type: xxxxx */
		*poffset += 14;
		*poffset += strlen(pmime->content_type);
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		pmime->f_type_params.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (pmime->f_type_params.read(&tag_len,
		       sizeof(uint32_t)) != MEM_END_OF_FILE) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			*poffset += tag_len + 4;
			pmime->f_type_params.seek(MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
			pmime->f_type_params.read(&val_len, sizeof(uint32_t));
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (0 != val_len) {
				*poffset += val_len + 1;
				pmime->f_type_params.seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
			}
		}
		/* \r\n for separate head and content */
		*poffset += 4;
	}
	if (pmime->mime_type == mime_type::single) {
		if (NULL != pmime->content_begin) {
			if (0 != pmime->content_length) {
				*poffset += pmime->content_length;
			} else {
				auto mgl = reinterpret_cast<MAIL *>(pmime->content_begin)->get_length();
				if (mgl < 0)
					return -1;
				*poffset += mgl;
			}
		} else {
			/* if there's nothing, just append an empty line */
			*poffset += 2;
		}
		return 0;
	}
	return mime_get_struct_mul(this, id_string, poffset, head_offset,
	       pcount, pbuff, length);;
}

static ssize_t mime_get_struct_mul(MIME *pmime, const char *id_string,
    size_t *poffset, size_t head_offset, size_t *pcount, char *pbuff,
    size_t length)
{
	size_t count = 0, i, buff_len = 0, tmp_len;
	MIME	*pmime_child;
	BOOL	has_submime;
	char temp_id[64], content_type[256];

	if (*pcount > 0) {
		pbuff[buff_len] = ',';
		buff_len++;
	}
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
	buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
	            "{\"id\":\"%s\",\"ctype\":\"%s\",\"head\":%zu,"
	            "\"begin\":%zu, \"length\":%zu}", id_string,
	            content_type, head_offset, *poffset,
	            head_offset + mgl - *poffset);
	if (buff_len >= length - 1) {
		return -1;
	}

	*pcount += 1;
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
		pmime_child = (MIME *)pnode->pdata;
		if ('\0' == id_string[0]) {
			snprintf(temp_id, 64, "%zu", count);
		} else {
			snprintf(temp_id, 64, "%s.%zu", id_string, count);
		}
		auto gsd = pmime_child->get_structure_digest(temp_id, poffset,
		           pcount, pbuff + buff_len, length - buff_len);
		if (gsd < 0 || buff_len + gsd >= length - 1)
			return -1;
		buff_len += gsd;
		pnode = pnode->get_sibling();
		count++;
	}
	if (!has_submime)
		*poffset += pmime->boundary_len + 6;
	*poffset += pmime->boundary_len + 4;
	if (NULL == pmime->last_boundary) {
		*poffset += 4;
	} else {
		tmp_len = pmime->content_length - (pmime->last_boundary -
		          pmime->content_begin);
		if (tmp_len > 0) {
			*poffset += tmp_len;
		} else if (0 == tmp_len) {
			*poffset += 2;
		}
	}
	if (buff_len >= length - 1) {
		return -1;
	}
	return buff_len;
}

static BOOL mime_parse_multiple(MIME *pmime)
{
	BOOL b_match;
	int boundary_len;
	char *ptr, *begin, *end;

#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime]: NULL pointer found in mime_parse_multiple");
		return FALSE;
	}
#endif
	if (NULL == pmime->content_begin) {
		return FALSE;
	}
	boundary_len = strlen(pmime->boundary_string);
	if (boundary_len <= 2) {
		return FALSE;
	}
	begin = strchr(pmime->boundary_string, '"');
	if (NULL != begin) {
		end = strchr(begin + 1, '"');
		if (NULL == end) {
			return FALSE;
		}
		boundary_len = end - begin - 1;
		memmove(pmime->boundary_string, begin + 1, boundary_len);
		pmime->boundary_string[boundary_len] = '\0';
	} 
	pmime->boundary_len = boundary_len;
	
	begin = pmime->content_begin;
	end = begin + pmime->content_length - boundary_len;
	for (ptr=begin; ptr < end; ptr++) {
		if (ptr[0] == '-' && ptr[1] == '-' &&
			0 == strncmp(pmime->boundary_string, ptr + 2,boundary_len)
			&& '\r' == ptr[2 + boundary_len] && 
			'\n' == ptr[3 + boundary_len]) {
			break;
		}
	}
	if (ptr == end) {
		return FALSE;
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
	if (!b_match) {
		pmime->last_boundary = pmime->content_begin + pmime->content_length;
		if (pmime->last_boundary < pmime->first_boundary +
			pmime->boundary_len + 4) {
			return FALSE;
		}
	} else {
		pmime->last_boundary = ptr + 1;
	}
	return TRUE;
}

static void mime_produce_boundary(MIME *pmime)
{
	char *begin, *end, *ptr, temp;
	char temp_boundary[VALUE_LEN];
    int boundary_len;


#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime]: NULL pointer found in mime_produce_boundary");
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
		temp = rand()%16;
		*ptr = (temp > 9)?(temp + 55):(temp + 48);
	}
	*ptr = '.';
	begin = end + 1;
	end = begin + 8;
	for (ptr=begin; ptr<end; ptr++) {
        temp = rand()%16;
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

static BOOL mime_check_ascii_printable(const char *astring)
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
