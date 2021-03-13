// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 * normally, MIME object does'n maintain its own content buffer, it just take
 * the reference of a mail object buffer, mark the begin, end and the content
 * point. if user uses mime_write_content function, the mime will then maintain
 * its own buffer
 */
#include <libHX/string.h>
#include <gromox/fileio.h>
#include <gromox/mail.hpp>
#include <gromox/mime.hpp>
#include <gromox/util.hpp>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <cstdio>

static BOOL mime_parse_multiple(MIME *pmime);

static void mime_produce_boundary(MIME *pmime);

static BOOL mime_check_ascii_printable(const char *astring);

bool mail_set_header(MAIL *mail, const char *hdr, const char *val)
{
	SIMPLE_TREE_NODE *node = simple_tree_get_root(&mail->tree);
	if (node == nullptr)
		return false;
	return mime_set_field(static_cast<MIME *>(node->pdata), hdr, val);
}

/*
 *	this is the MIME's construct function
 *	@param
 *		pmime [in,out]	MIME object
 *		palloc [in]		allocator for mem files			
 */
void mime_init(MIME *pmime, LIB_BUFFER *palloc)
{
#ifdef _DEBUG_UMTA
	if (NULL == pmime || NULL == palloc) {
		debug_info("[mime]: NULL pointer found in mime_init");
		return;
	}
#endif
	memset(&pmime->node, 0, sizeof(SIMPLE_TREE_NODE));
	pmime->node.pdata		 = pmime;
	pmime->mime_type         = NONE_MIME;
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
	mem_file_init(&pmime->f_type_params, palloc);
	mem_file_init(&pmime->f_other_fields, palloc);
	
}

/*
 *	this is the MIME's destruct function
 *	@param
 *		pmime [in,out]	MIME object
 */
void mime_free(MIME *pmime)
{
	MIME *pmime_child;
	SIMPLE_TREE_NODE *pnode;
#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime]: NULL pointer found in mime_free");
		return;
	}
#endif
	if (SINGLE_MIME == pmime->mime_type) {
		if (TRUE == pmime->content_touched && NULL != pmime->content_begin) {
			if (0 != pmime->content_length) {
				free(pmime->content_begin);
			}
			pmime->content_begin = NULL;
			pmime->content_length = 0;
		}
	} else if (MULTIPLE_MIME == pmime->mime_type) {
		pnode = simple_tree_node_get_child(&pmime->node);
        while (NULL != pnode) {
			pmime_child = (MIME*)pnode->pdata;
            mime_free(pmime_child);
			pnode = simple_tree_node_get_sibling(pnode);
        }
	}
	mem_file_free(&pmime->f_type_params);
	mem_file_free(&pmime->f_other_fields);
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
BOOL mime_retrieve(MIME *pmime_parent,
	MIME *pmime, char* in_buff, size_t length)
{

	long current_offset = 0, parsed_length = 0;
	MIME_FIELD mime_field;

#ifdef _DEBUG_UMTA
	if (NULL == pmime || NULL == in_buff) {
		debug_info("[mime]: NULL pointer found in mime_retrieve");
		return FALSE;
	}
#endif
	
	mime_clear(pmime);
	if (0 == length) {
		/* in case of NULL content, we think such MIME
		 * is a NULL application/octet-stream
		 */
		pmime->head_touched = FALSE;
		pmime->content_begin = NULL;
		pmime->content_length = 0;
		pmime->mime_type = SINGLE_MIME;
		return TRUE;
	}
	while (current_offset <= length) {
		parsed_length = parse_mime_field(in_buff + current_offset,
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
				if (0 == strncasecmp(pmime->content_type, "multipart/", 10)) {
					pmime->mime_type = MULTIPLE_MIME;
				} else {
					pmime->mime_type = SINGLE_MIME;
				}
			} else {
				mem_file_write(&pmime->f_other_fields,
						(char*)&mime_field.field_name_len,
						sizeof(mime_field.field_name_len));
				mem_file_write(&pmime->f_other_fields,
						mime_field.field_name,
						mime_field.field_name_len);
				mem_file_write(&pmime->f_other_fields,
			            (char*)&mime_field.field_value_len,
				        sizeof(mime_field.field_value_len));
				mem_file_write(&pmime->f_other_fields,
						mime_field.field_value,
						mime_field.field_value_len);
			}
			if ('\r' == in_buff[current_offset]) {
				pmime->head_begin = in_buff;
				pmime->head_length = current_offset;
				/*
				 * if a empty line is meet, end of mail head parse
				 * skip the empty line, which separate the head and 
				 * content \r\n 
				 */
				current_offset += 2;

				if (current_offset > length) {
					mime_clear(pmime);
					return FALSE;
				} else if (current_offset == length) {
					pmime->content_begin = NULL;
					pmime->content_length = 0;
					if (MULTIPLE_MIME == pmime->mime_type) {
						pmime->mime_type = SINGLE_MIME;
					}
				} else {
					pmime->content_begin = in_buff + current_offset;
					pmime->content_length = length - current_offset;
				}
				if (MULTIPLE_MIME == pmime->mime_type) {
					if (FALSE  == mime_get_content_param(pmime, "boundary",
						pmime->boundary_string, VALUE_LEN - 1)) {
						pmime->mime_type = SINGLE_MIME;
					}
					if (FALSE == mime_parse_multiple(pmime)) {
						pmime->mime_type = SINGLE_MIME;
					}
				} else if (NONE_MIME == pmime->mime_type) {
					/* old simplest unix style mail */
					strcpy(pmime->content_type, "text/plain");
					pmime->mime_type = SINGLE_MIME;
				}
				return TRUE;
			}
		} else {
			if (0 == current_offset) {
				pmime->head_touched = TRUE;
				pmime->content_begin = in_buff;
				pmime->content_length = length;
				/* old simplest unix style mail */
				strcpy(pmime->content_type, "text/plain");
				pmime->mime_type = SINGLE_MIME;
				return TRUE;
			} else {
				pmime->head_begin = in_buff;
				pmime->head_length = current_offset;
				/*
				 * there's not empty line, which separate the head and 
				 * content \r\n 
				 */

				if (current_offset > length) {
					mime_clear(pmime);
					return FALSE;
				} else if (current_offset == length) {
					pmime->content_begin = NULL;
					pmime->content_length = 0;
					if (MULTIPLE_MIME == pmime->mime_type) {
						pmime->mime_type = SINGLE_MIME;
					}
				} else {
					pmime->content_begin = in_buff + current_offset;
					pmime->content_length = length - current_offset;
				}
				if (MULTIPLE_MIME == pmime->mime_type) {
					if (FALSE  == mime_get_content_param(pmime, "boundary",
						pmime->boundary_string, VALUE_LEN - 1)) {
						pmime->mime_type = SINGLE_MIME;
					}
					if (FALSE == mime_parse_multiple(pmime)) {
						pmime->mime_type = SINGLE_MIME;
					}
				} else if (NONE_MIME == pmime->mime_type) {
					if (NULL != pmime_parent && 0 == strcasecmp(
						"multipart/digest", pmime->content_type)) {
						strcpy(pmime->content_type, "message/rfc822");
					} else {
						/* old simplest unix style mail */
						strcpy(pmime->content_type, "text/plain");
					}
					pmime->mime_type = SINGLE_MIME;
				}
				return TRUE;
			}
		}
	}
	mime_clear(pmime);
	return FALSE;
}

/*
 *	clear the MIME object
 *	@param
 *		pmime [in,out]	pointer to MIME object
 */
void mime_clear(MIME *pmime)
{
#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime]: NULL pointer found in mime_clear");
		return;
	}
#endif
	
	if (SINGLE_MIME == pmime->mime_type && TRUE == pmime->content_touched
		&& NULL != pmime->content_begin) {
		if (0 != pmime->content_length) {
			free(pmime->content_begin);
		}
		pmime->content_begin = NULL;
		pmime->content_length = 0;
	}
    pmime->mime_type         = NONE_MIME;
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
	mem_file_clear(&pmime->f_type_params);
	mem_file_clear(&pmime->f_other_fields);

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
BOOL mime_write_content(MIME *pmime, const char *pcontent, size_t length,
	int encoding_type)
{
	size_t i, j;
	char *pbuff;
	/* align the buffer with 64K */
	size_t buff_length;
	BOOL added_crlf;
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime || (NULL == pcontent && 0 != length)) {
		debug_info("[mime]: NULL pointer found in mime_write_content");
		return FALSE;
	}
#endif
	if (SINGLE_MIME != pmime->mime_type) {
		return FALSE;
	}
	if (MIME_ENCODING_BASE64 != encoding_type &&
		MIME_ENCODING_QP != encoding_type &&
		MIME_ENCODING_NONE != encoding_type) {
		debug_info("[mime]: encoding type should be one of "
			"MIME_ENCODING_NONE, MIME_ENCODING_BASE64, MIME_ENCODING_QP");
		return FALSE;
	}
	if (TRUE == pmime->content_touched && NULL != pmime->content_begin) {
		if (0 != pmime->content_length) {
			free(pmime->content_begin);
		}
	}
	pmime->content_begin = NULL;
	pmime->content_length = 0;
	pmime->content_touched = TRUE;
	mime_remove_field(pmime, "Content-Transfer-Encoding");
	if (0 == length) {
		if (MIME_ENCODING_QP == encoding_type) {
			mime_set_field(pmime, "Content-Transfer-Encoding",
				"quoted-printable");
		} else if (MIME_ENCODING_BASE64 == encoding_type) {
			mime_set_field(pmime, "Content-Transfer-Encoding", "base64");
		}
		return TRUE;
	}
	switch (encoding_type) {
	case MIME_ENCODING_NONE:
		/* should add '\r\n' at the end of buffer if it misses */
		if ('\n' != pcontent[length - 1]) {
			added_crlf = TRUE;
		} else {
			added_crlf = FALSE;
		}
		buff_length = ((2 * length) / (64 * 1024) + 1) * 64 * 1024;
		pmime->content_begin = static_cast<char *>(malloc(buff_length));
		if (NULL == pmime->content_begin) {
			return FALSE;
		}
		for (i=0,j=0; i<length; i++,j++) {
			if ('.' == pcontent[i]) {
				if (0 == i) {
					pmime->content_begin[j] = '.';
					j ++;
				} else {
					if (i > 2 && '\n' == pcontent[i - 1] &&
						'\r' == pcontent[i - 2]) {
						pmime->content_begin[j] = '.';
						j ++;
					}
				}
			}
			pmime->content_begin[j] = pcontent[i];
		}
		length = j;
		if (TRUE == added_crlf) {
			memcpy(pmime->content_begin + length, "\r\n", 2);
			pmime->content_length = length + 2;
		} else {
			pmime->content_length = length;
		}
		return TRUE;
	case MIME_ENCODING_QP:
		buff_length = ((4 * length) / (64 * 1024) + 1) * 64 * 1024;
		pbuff = static_cast<char *>(malloc(buff_length));
		if (NULL == pbuff) {
			return FALSE;
		}
		pmime->content_begin = static_cast<char *>(malloc(buff_length));
		if (NULL == pmime->content_begin) {
			free(pbuff);
			return FALSE;
		}
		length = qp_encode_ex(pbuff, buff_length, pcontent, length);
		if ('\n' != pbuff[length - 1]) {
			memcpy(pbuff + length, "\r\n", 2);
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
		free(pbuff);
		pmime->content_length = j;
		mime_set_field(pmime, "Content-Transfer-Encoding", "quoted-printable");
		return TRUE;
	case MIME_ENCODING_BASE64:
		buff_length = ((2 * length) / (64 * 1024) + 1) * 64 * 1024;
		pmime->content_begin = static_cast<char *>(malloc(buff_length));
		if (NULL == pmime->content_begin) {
			return FALSE;
		}
		encode64_ex(pcontent, length, pmime->content_begin, buff_length,
				&pmime->content_length);
		mime_set_field(pmime, "Content-Transfer-Encoding", "base64");
		return TRUE;
	}
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
BOOL mime_write_mail(MIME *pmime, MAIL *pmail)
{
#ifdef _DEBUG_UMTA
    if (NULL == pmime || NULL == pmail) {
        debug_info("[mime]: NULL pointer found in mime_write_mail");
        return FALSE;
    }
#endif
    if (SINGLE_MIME != pmime->mime_type) {
        return FALSE;
    }
    if (TRUE == pmime->content_touched && NULL != pmime->content_begin) {
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
	mime_set_field(pmime, "Content-Transfer-Encoding", "8bit");
	return TRUE;
}

/*
 *	set the content type of the MIME object
 *	@param
 *		pmime [in,out]		indicate the MIME object
 *		content_type [in]	buffer containing content type
 */
BOOL mime_set_content_type(MIME *pmime, const char *content_type)
{
	BOOL b_multiple;

#ifdef _DEBUG_UMTA
	if (NULL == pmime || NULL == content_type) {
		debug_info("[mime]: NULL pointer found in mime_set_content_type");
		return FALSE;
	}
#endif
	
	b_multiple = FALSE;
	if (0 == strncasecmp(content_type, "multipart/", 10)) {
		b_multiple = TRUE;
	}
	if (SINGLE_MIME == pmime->mime_type) {
		if (TRUE == b_multiple) {
			return FALSE;
		}
	} else if (NONE_MIME == pmime->mime_type) {
		if (TRUE == b_multiple) {
			mime_produce_boundary(pmime);
			pmime->mime_type = MULTIPLE_MIME;
		} else {
			pmime->mime_type = SINGLE_MIME;
		}
	}
	strncpy(pmime->content_type, content_type, 255);
	pmime->content_type[255] = '\0';
	pmime->head_touched = TRUE;
	return TRUE;
}

/*
 *	get the content type of the MIME object
 *	@param
 *		pmime [in,out]		indicate the mime object
 *	@return
 *		content type string
 */
const char *mime_get_content_type(MIME *pmime)
{
#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime]: NULL pointer found in mime_get_content_type");
		return NULL;
	}
#endif
	return pmime->content_type;
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
BOOL mime_enum_field(MIME *pmime, MIME_FIELD_ENUM enum_func, void *pparam)
{
	int	tag_len, val_len;
	char tmp_tag[MIME_NAME_LEN];
	char tmp_value[MIME_FIELD_LEN];
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime]: NULL pointer found in mime_enum_field");
		return FALSE;
	}
#endif
	if (FALSE == enum_func("Content-Type", pmime->content_type, pparam)) {
		return FALSE;
	}
	mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, 0, 
		MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_read(&pmime->f_other_fields,
		&tag_len, sizeof(int))) {
		mem_file_read(&pmime->f_other_fields, tmp_tag, tag_len);
		tmp_tag[tag_len] = '\0';
		mem_file_read(&pmime->f_other_fields, &val_len, sizeof(int));
		mem_file_read(&pmime->f_other_fields, tmp_value, val_len);
		tmp_value[val_len] = '\0';
		if (FALSE == enum_func(tmp_tag, tmp_value, pparam)) {
			return FALSE;
		}
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
	mem_file_seek(&pmime->f_type_params, MEM_FILE_READ_PTR, 0, 
		MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_read(&pmime->f_type_params,
		(char*)&tag_len, sizeof(int))) {
		/* content-type: xxxxx"; "yyyyy */
		if (offset + 4 + tag_len >= length) {
			return FALSE;
		}
		memcpy(value + offset, "; ", 2);
		offset += 2;
		mem_file_read(&pmime->f_type_params, tmp_buff, tag_len);
		memcpy(value + offset, tmp_buff, tag_len);
		offset += tag_len;
		mem_file_read(&pmime->f_type_params, (char*)&val_len, sizeof(int));
		mem_file_read(&pmime->f_type_params, tmp_buff, val_len);
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
BOOL mime_get_field(MIME *pmime, const char *tag, char *value, int length)
{
	int tag_len, val_len;
	char tmp_buff[MIME_NAME_LEN];
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime || NULL == tag || NULL == value) {
		debug_info("[mime]: NULL pointer found in mime_get_field");
		return FALSE;
	}
#endif
	if (0 == strcasecmp(tag, "Content-Type")) {
		return mime_get_content_type_field(pmime, value, length);
	}
	mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, 0, 
		MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_read(&pmime->f_other_fields,
		&tag_len, sizeof(int))) {
		mem_file_read(&pmime->f_other_fields, tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		mem_file_read(&pmime->f_other_fields, &val_len, sizeof(int));
		if (0 == strcasecmp(tag, tmp_buff)) {
			length = (length > val_len)?val_len:(length - 1);
			mem_file_read(&pmime->f_other_fields, value, length);
			value[length] = '\0';
			return TRUE;
		} 
		mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR,
			val_len, MEM_FILE_SEEK_CUR);
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
int mime_get_field_num(MIME *pmime, const char *tag)
{
	int i;
	int	tag_len, val_len;
	char tmp_buff[MIME_NAME_LEN];

#ifdef _DEBUG_UMTA
	if (NULL == pmime || NULL == tag) {
		debug_info("[mime]: NULL pointer found in mime_get_field_num");
		return 0;
	}
#endif
	if (0 == strcasecmp(tag, "Content-Type")) {
		return 1;
	}
	i = 0;
	mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, 0, 
		MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_read(&pmime->f_other_fields,
		&tag_len, sizeof(int))) {
		mem_file_read(&pmime->f_other_fields, tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		mem_file_read(&pmime->f_other_fields, &val_len, sizeof(int));
		if (0 == strcasecmp(tag, tmp_buff)) {
			i ++;
		}
		mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR,
			val_len, MEM_FILE_SEEK_CUR);
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
BOOL mime_search_field(MIME *pmime, const char *tag, int order, char *value,
	int length)
{
	int i;
	int	tag_len, val_len;
	char tmp_buff[MIME_FIELD_LEN];
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime || NULL == tag || NULL == value) {
		debug_info("[mime]: NULL pointer found in mime_search_field");
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
	mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, 0, 
		MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_read(&pmime->f_other_fields,
		&tag_len, sizeof(int))) {
		mem_file_read(&pmime->f_other_fields, tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		mem_file_read(&pmime->f_other_fields, &val_len, sizeof(int));
		if (0 == strcasecmp(tag, tmp_buff)) {
			i ++;
			if (i == order) {
				length = (length > val_len)?val_len:(length - 1);
				mem_file_read(&pmime->f_other_fields, value, length);
				value[length] = '\0';
				return TRUE;
			}
		} 
		mem_file_read(&pmime->f_other_fields, tmp_buff, val_len);
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
BOOL mime_set_field(MIME *pmime, const char *tag, const char *value)
{
	MEM_FILE file_tmp;
	int		tag_len, val_len;
	char	tmp_buff[MIME_FIELD_LEN];
	BOOL	found_tag = FALSE;
	int		i, mark;
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime || NULL == tag || NULL == value) {
		debug_info("[mime]: NULL pointer found in mime_set_field");
		return FALSE;
	}
#endif
	if (0 == strcasecmp(tag, "Content-Type")) {
		mem_file_clear(&pmime->f_type_params);
		parse_field_value((char*)value, strlen(value), tmp_buff, 256, 
			&pmime->f_type_params);
		if (FALSE == mime_set_content_type(pmime, tmp_buff)) {
			mem_file_clear(&pmime->f_type_params);
			return FALSE;
		}
		return TRUE;
	}
	mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, 0,
		MEM_FILE_SEEK_BEGIN);
	mark = -1;
	while (MEM_END_OF_FILE != mem_file_read(&pmime->f_other_fields,
		&tag_len, sizeof(int))) {
		mark ++;
		mem_file_read(&pmime->f_other_fields, tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		if (0 == strcasecmp(tag, tmp_buff)) {
			found_tag = TRUE;
			break;
		} 
		mem_file_read(&pmime->f_other_fields, &val_len, sizeof(int));
		mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, val_len,
			MEM_FILE_SEEK_CUR);
	}
	if (FALSE == found_tag){
		tag_len = strlen(tag);
		val_len = strlen(value);
		mem_file_write(&pmime->f_other_fields, (char*)&tag_len, sizeof(int));
		mem_file_write(&pmime->f_other_fields, (char*)tag, tag_len);
		mem_file_write(&pmime->f_other_fields, (char*)&val_len, sizeof(int));
		mem_file_write(&pmime->f_other_fields, (char*)value, val_len);
	} else {
		mem_file_init(&file_tmp, pmime->f_other_fields.allocator);
		mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, 0, 
			MEM_FILE_SEEK_BEGIN);
		i = 0;
		while (MEM_END_OF_FILE != mem_file_read(&pmime->f_other_fields, 
			&tag_len, sizeof(int))) {
			mem_file_read(&pmime->f_other_fields, tmp_buff, tag_len);
			if (i != mark) {
				mem_file_write(&file_tmp, (char*)&tag_len, sizeof(int));
				mem_file_write(&file_tmp, tmp_buff, tag_len);
			}
			mem_file_read(&pmime->f_other_fields, &val_len, sizeof(int));
			mem_file_read(&pmime->f_other_fields, tmp_buff, val_len);
			if (i != mark) {
				mem_file_write(&file_tmp, (char*)&val_len, sizeof(int));
				mem_file_write(&file_tmp, tmp_buff, val_len);
			}
			i ++;
		}
		/* write the new tag-value at the end of mem file */
		tag_len = strlen(tag);
		val_len = strlen(value);
		mem_file_write(&file_tmp, (char*)&tag_len, sizeof(int));
		mem_file_write(&file_tmp, (char*)tag, tag_len);
		mem_file_write(&file_tmp, (char*)&val_len, sizeof(int));
		mem_file_write(&file_tmp, (char*)value, val_len);
		mem_file_copy(&file_tmp, &pmime->f_other_fields);
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
BOOL mime_append_field(MIME *pmime, const char *tag, const char *value)
{
	int	tag_len, val_len;
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime || NULL == tag || NULL == value) {
		debug_info("[mime]: NULL pointer found in mime_append_field");
		return FALSE;
	}
#endif
	if (0 == strcasecmp(tag, "Content-Type")) {
		return FALSE;
	}
	tag_len = strlen(tag);
	val_len = strlen(value);
	mem_file_write(&pmime->f_other_fields, (char*)&tag_len, sizeof(int));
	mem_file_write(&pmime->f_other_fields, (char*)tag, tag_len);
	mem_file_write(&pmime->f_other_fields, (char*)&val_len, sizeof(int));
	mem_file_write(&pmime->f_other_fields, (char*)value, val_len);
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
BOOL mime_remove_field(MIME *pmime, const char *tag)
{
	BOOL found_tag;
	MEM_FILE file_tmp;
	char tmp_buff[MIME_FIELD_LEN];
	int tag_len, val_len;

	if (0 == strcasecmp(tag, "Content-Type")) {
		return FALSE;
	}
	mem_file_init(&file_tmp, pmime->f_other_fields.allocator);
	mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, 0,
		MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_read(&pmime->f_other_fields,
		&tag_len, sizeof(int))) {
		mem_file_read(&pmime->f_other_fields, tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		if (0 == strcasecmp(tag, tmp_buff)) {
			found_tag = TRUE;
			mem_file_read(&pmime->f_other_fields, &val_len, sizeof(int));
			mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, val_len,
				MEM_FILE_SEEK_CUR);
		} else {
			mem_file_write(&file_tmp, (char*)&tag_len, sizeof(int));
			mem_file_write(&file_tmp, (char*)tmp_buff, tag_len);
			mem_file_read(&pmime->f_other_fields, &val_len, sizeof(int));
			mem_file_read(&pmime->f_other_fields, tmp_buff, val_len);
			mem_file_write(&file_tmp, (char*)&val_len, sizeof(int));
			mem_file_write(&file_tmp, (char*)tmp_buff, val_len);
		}
	}
	if (TRUE == found_tag) {
		mem_file_copy(&file_tmp, &pmime->f_other_fields);
	}
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
BOOL mime_get_content_param(MIME *pmime, const char *tag, char *value,
	int length)
{
	int	tag_len, val_len;
	char	tmp_buff[MIME_FIELD_LEN];
	int		distance;
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime || NULL == tag || NULL == value) {
		debug_info("[mime]: NULL pointer found in mime_get_content_param");
		return FALSE;
	}
#endif
	mem_file_seek(&pmime->f_type_params, MEM_FILE_READ_PTR, 0, 
		MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_read(&pmime->f_type_params,
		&tag_len, sizeof(int))) {
		mem_file_read(&pmime->f_type_params, tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		if (0 == strcasecmp(tag, tmp_buff)) {
			mem_file_read(&pmime->f_type_params, &val_len, sizeof(int));
			distance = (val_len > length - 1)?(length - 1):val_len;
			mem_file_read(&pmime->f_type_params, value, distance);
			value[distance] = '\0';
			return TRUE;
		} 
		mem_file_read(&pmime->f_type_params, &val_len, sizeof(int));
		mem_file_read(&pmime->f_type_params, tmp_buff, val_len);
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
BOOL mime_set_content_param(MIME *pmime, const char *tag, const char *value)
{
	MEM_FILE file_tmp;
	int	tag_len, val_len;
	char	tmp_buff[MIME_FIELD_LEN];
	BOOL	found_tag = FALSE;
	int		i, mark, boundary_len;
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime || NULL == tag || NULL == value) {
		debug_info("[mime]: NULL pointer found in mime_set_field");
		return FALSE;
	}
#endif
	if (0 == strcasecmp(tag, "boundary")) {
		boundary_len = strlen(value);
		if (boundary_len > VALUE_LEN - 3 || boundary_len < 3) {
			return FALSE;
		}
		if ('"' == value[0]) {
			if ('"' != value[boundary_len - 1]) {
				return FALSE;
			}
			memcpy(pmime->boundary_string, value + 1, boundary_len - 1);
			pmime->boundary_string[boundary_len - 1] = '\0';
			pmime->boundary_len = boundary_len - 2;
		} else {
			memcpy(pmime->boundary_string, value, boundary_len);
			pmime->boundary_string[boundary_len] = '\0';
			pmime->boundary_len = boundary_len;
		}
	}
	mem_file_seek(&pmime->f_type_params, MEM_FILE_READ_PTR, 0, 
		MEM_FILE_SEEK_BEGIN);
	mark = -1;
	while (MEM_END_OF_FILE != mem_file_read(&pmime->f_type_params,
		&tag_len, sizeof(int))) {
		mark ++;
		mem_file_read(&pmime->f_type_params, tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		if (0 == strcasecmp(tag, tmp_buff)) {
			found_tag = TRUE;
			break;
		} 
		mem_file_read(&pmime->f_type_params, &val_len, sizeof(int));
		mem_file_read(&pmime->f_type_params, tmp_buff, val_len);
	}
	if (FALSE == found_tag){
		tag_len = strlen(tag);
		val_len = strlen(value);
		mem_file_write(&pmime->f_type_params, (char*)&tag_len, sizeof(int));
		mem_file_write(&pmime->f_type_params, (char*)tag, tag_len);
		mem_file_write(&pmime->f_type_params, (char*)&val_len, sizeof(int));
		mem_file_write(&pmime->f_type_params, (char*)value, val_len);
	} else {
		mem_file_init(&file_tmp, pmime->f_type_params.allocator);
		mem_file_seek(&pmime->f_type_params, MEM_FILE_READ_PTR, 0, 
			MEM_FILE_SEEK_BEGIN);
		i = 0;
		while (MEM_END_OF_FILE != mem_file_read(&pmime->f_type_params, 
			(char*)&tag_len, sizeof(int))) {
			mem_file_read(&pmime->f_type_params, tmp_buff, tag_len);
			if (i != mark) {
				mem_file_write(&file_tmp, (char*)&tag_len, sizeof(int));
				mem_file_write(&file_tmp, tmp_buff, tag_len);
			}
			mem_file_read(&pmime->f_type_params, (char*)&val_len, sizeof(int));
			mem_file_read(&pmime->f_type_params, tmp_buff, val_len);
			if (i != mark) {
				mem_file_write(&file_tmp, (char*)&val_len, sizeof(int));
				mem_file_write(&file_tmp, tmp_buff, val_len);
			}
			i ++;
		}
		/* write the new tag-value at the end of mem file */
		tag_len = strlen(tag);
		val_len = strlen(value);
		mem_file_write(&file_tmp, (char*)&tag_len, sizeof(int));
		mem_file_write(&file_tmp, (char*)tag, tag_len);
		mem_file_write(&file_tmp, (char*)&val_len, sizeof(int));
		mem_file_write(&file_tmp, (char*)value, val_len);
		mem_file_copy(&file_tmp, &pmime->f_type_params);
		mem_file_free(&file_tmp);
	}
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
BOOL mime_serialize(MIME *pmime, STREAM *pstream)
{
	int		tag_len, val_len;
	long	len, tmp_len;
	char	tmp_buff[MIME_FIELD_LEN];
	MIME	*pmime_child;
	BOOL	has_submime;
	SIMPLE_TREE_NODE *pnode;
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime || NULL == pstream) {
		debug_info("[mime]: NULL pointer found in mime_serialize");
		return FALSE;
	}
#endif
	if (NONE_MIME == pmime->mime_type) {
		return FALSE;
	}
	if (FALSE == pmime->head_touched){
		/* the original buffer contains \r\n */
		if (pmime->head_begin + pmime->head_length + 2 == pmime->content_begin){
			stream_write(pstream, pmime->head_begin, pmime->head_length + 2);
		} else {
			stream_write(pstream, pmime->head_begin, pmime->head_length);
			stream_write(pstream, "\r\n", 2);
		}
	} else {	
		mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, 0, 
			MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_read(&pmime->f_other_fields, 
			(char*)&tag_len, sizeof(int))) {
			/* xxxxx: yyyyy */
			mem_file_read(&pmime->f_other_fields, tmp_buff, tag_len);
			stream_write(pstream, tmp_buff, tag_len);
			stream_write(pstream, ": ", 2);
			mem_file_read(&pmime->f_other_fields, (char*)&val_len,
				sizeof(int));
			mem_file_read(&pmime->f_other_fields, tmp_buff, val_len);
			stream_write(pstream, tmp_buff, val_len);
			/* \r\n */
			stream_write(pstream, "\r\n", 2);
		}

		/* Content-Type: xxxxx */
		stream_write(pstream, "Content-Type: ", 14);
		len = strlen(pmime->content_type);
		stream_write(pstream, pmime->content_type, len);
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		mem_file_seek(&pmime->f_type_params, MEM_FILE_READ_PTR, 0, 
			MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_read(&pmime->f_type_params, 
			(char*)&tag_len, sizeof(int))) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			stream_write(pstream, ";\r\n\t", 4);
			mem_file_read(&pmime->f_type_params, tmp_buff, tag_len);
			stream_write(pstream, tmp_buff, tag_len);
			mem_file_read(&pmime->f_type_params, (char*)&val_len, 
				sizeof(int));
			mem_file_read(&pmime->f_type_params, tmp_buff, val_len);
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (0 != val_len) {
				stream_write(pstream, "=", 1);
				stream_write(pstream, tmp_buff, val_len);
			}
		}
		/* \r\n for separate head and content */
		stream_write(pstream, "\r\n\r\n", 4);
	}
	if (SINGLE_MIME == pmime->mime_type) {
		if (NULL != pmime->content_begin) {
			if (0 != pmime->content_length) {
				stream_write(pstream, pmime->content_begin,
					pmime->content_length);
			} else {
				mail_serialize(reinterpret_cast<MAIL *>(pmime->content_begin), pstream);
			}
		} else {
			/* if there's nothing, just append an empty line */
			stream_write(pstream, "\r\n", 2);
		}
	} else {
		if (NULL == pmime->first_boundary) {
			stream_write(pstream, "This is a multi-part message "
						"in MIME format.\r\n\r\n", 48);
		} else {
			stream_write(pstream, pmime->content_begin,
				pmime->first_boundary - pmime->content_begin);
		}
		pnode = simple_tree_node_get_child(&pmime->node);
		has_submime = FALSE;
        while (NULL != pnode) {
			has_submime = TRUE;
			stream_write(pstream, "--", 2);
			stream_write(pstream, pmime->boundary_string, pmime->boundary_len);
			stream_write(pstream, "\r\n", 2);
			pmime_child = (MIME*)pnode->pdata;
			if (FALSE == mime_serialize(pmime_child, pstream)) {
				return FALSE;
			}
			pnode = simple_tree_node_get_sibling(pnode);
		}
		if (FALSE == has_submime) {
			stream_write(pstream, "--", 2);
			stream_write(pstream, pmime->boundary_string, pmime->boundary_len);
			stream_write(pstream, "\r\n\r\n", 4);
		}
		stream_write(pstream, "--", 2);
		stream_write(pstream, pmime->boundary_string, pmime->boundary_len);
		stream_write(pstream, "--", 2);
		if (NULL == pmime->last_boundary) {
			stream_write(pstream, "\r\n\r\n", 4);
		} else {
			tmp_len = pmime->content_length -
					(pmime->last_boundary - pmime->content_begin);
			if (tmp_len > 0) {
				stream_write(pstream, pmime->last_boundary, tmp_len);
			} else if (0 == tmp_len) {
				stream_write(pstream, "\r\n", 2);
			} else {
				debug_info("[mime]: fatal error in mime_serialize");
			}
		}
	}
	return TRUE;
}

static BOOL mime_read_mutlipart_content(MIME *pmime,
	char *out_buff, size_t *plength)
{
	void *ptr;
	size_t offset, tmp_len;
	unsigned int buff_size;
	size_t tmp_size;
	BOOL has_submime;
	STREAM tmp_stream;
	MIME *pmime_child;
	SIMPLE_TREE_NODE *pnode;
	LIB_BUFFER *pallocator;
	
	tmp_size = mime_get_length(pmime);
	pallocator = lib_buffer_init(STREAM_ALLOC_SIZE,
			tmp_size / STREAM_BLOCK_SIZE + 1, FALSE);
	if (NULL == pallocator) {
		debug_info("[mime]: Failed to init lib buffer"
				" in mime_read_mutlipart_content");
		*plength = 0;
		return FALSE;
	}
	stream_init(&tmp_stream, pallocator);
	if (NULL == pmime->first_boundary) {
		stream_write(&tmp_stream,
			"This is a multi-part message "
			"in MIME format.\r\n\r\n", 48);
	} else {
		stream_write(&tmp_stream, pmime->content_begin,
			pmime->first_boundary - pmime->content_begin);
	}
	pnode = simple_tree_node_get_child(&pmime->node);
	has_submime = FALSE;
	while (NULL != pnode) {
		has_submime = TRUE;
		stream_write(&tmp_stream, "--", 2);
		stream_write(&tmp_stream, pmime->boundary_string, pmime->boundary_len);
		stream_write(&tmp_stream, "\r\n", 2);
		pmime_child = (MIME*)pnode->pdata;
		if (FALSE == mime_serialize(pmime_child, &tmp_stream)) {
			stream_free(&tmp_stream);
			lib_buffer_free(pallocator);
			return FALSE;
		}
		pnode = simple_tree_node_get_sibling(pnode);
	}
	if (FALSE == has_submime) {
		stream_write(&tmp_stream, "--", 2);
		stream_write(&tmp_stream, pmime->boundary_string, pmime->boundary_len);
		stream_write(&tmp_stream, "\r\n\r\n", 4);
	}
	stream_write(&tmp_stream, "--", 2);
	stream_write(&tmp_stream, pmime->boundary_string, pmime->boundary_len);
	stream_write(&tmp_stream, "--", 2);
	if (NULL == pmime->last_boundary) {
		stream_write(&tmp_stream, "\r\n\r\n", 4);
	} else {
		tmp_len = pmime->content_length -
				(pmime->last_boundary - pmime->content_begin);
		if (tmp_len > 0) {
			stream_write(&tmp_stream, pmime->last_boundary, tmp_len);
		} else if (0 == tmp_len) {
			stream_write(&tmp_stream, "\r\n", 2);
		} else {
			debug_info("[mime]: fatal error in mime_read_mutlipart_content");
		}
	}
	offset = 0;
	buff_size = STREAM_BLOCK_SIZE;
	while ((ptr = stream_getbuffer_for_reading(&tmp_stream, &buff_size))) {
		memcpy(out_buff + offset, ptr, buff_size);
		offset += buff_size;
		buff_size = STREAM_BLOCK_SIZE;
	}
	stream_free(&tmp_stream);
	lib_buffer_free(pallocator);
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
BOOL mime_read_head(MIME *pmime, char *out_buff, size_t *plength)
{
	int		tag_len, val_len;
	size_t	len, offset;
	char	tmp_buff[MIME_FIELD_LEN + MIME_NAME_LEN + 4];
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime]: NULL pointer found in mime_read_head");
		return FALSE;
	}
#endif
	if (NONE_MIME == pmime->mime_type) {
#ifdef _DEBUG_UMTA
		debug_info("[mime]: mime content type is not set");
#endif
		return FALSE;
	}
	if (FALSE == pmime->head_touched){
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
	mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, 0, 
		MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_read(&pmime->f_other_fields, 
		(char*)&tag_len, sizeof(int))) {
		/* xxxxx: yyyyy */
		mem_file_read(&pmime->f_other_fields, tmp_buff, tag_len);
		len = tag_len;
		memcpy(tmp_buff + len, ": ", 2);
		len += 2;
		mem_file_read(&pmime->f_other_fields, (char*)&val_len,
			sizeof(int));
		mem_file_read(&pmime->f_other_fields, tmp_buff + len, val_len);
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
	mem_file_seek(&pmime->f_type_params, MEM_FILE_READ_PTR, 0, 
		MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_read(&pmime->f_type_params, 
		(char*)&tag_len, sizeof(int))) {
		/* content-type: xxxxx"; \r\n\t"yyyyy */
		if (len > MIME_FIELD_LEN + MIME_NAME_LEN - tag_len) {
			return FALSE;
		}
		memcpy(tmp_buff + len, ";\r\n\t", 4);
		len += 4;
		mem_file_read(&pmime->f_type_params, tmp_buff + len, tag_len);
		len += tag_len;
		mem_file_read(&pmime->f_type_params, (char*)&val_len, 
			sizeof(int));
		if (len > MIME_FIELD_LEN + MIME_NAME_LEN + 3 - val_len) {
			return FALSE;
		}
		/* content_type: xxxxx; \r\n\tyyyyy=zzz */
		if (0 != val_len) {
			memcpy(tmp_buff + len, "=", 1);
			len += 1;
			mem_file_read(&pmime->f_type_params, tmp_buff + len, val_len);
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
BOOL mime_read_content(MIME *pmime, char *out_buff, size_t *plength)
{
	STREAM tmp_stream;
	void *ptr;
	int encoding_type;
	char encoding[256], *pbuff;
	LIB_BUFFER *pallocator;
	size_t i, offset, max_length, tmp_len;
	unsigned int buff_size;
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime || NULL == out_buff || NULL == plength) {
		debug_info("[mime]: NULL pointer found in mime_read_content");
		return FALSE;
	}
#endif
	max_length = *plength;
	if (NONE_MIME == pmime->mime_type) {
		*plength = 0;
		return FALSE;
	}
	if (MULTIPLE_MIME == pmime->mime_type) {
		return mime_read_mutlipart_content(pmime, out_buff, plength);
	}
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
		auto mail_len = mail_get_length(reinterpret_cast<MAIL *>(pmime->content_begin));
		if (mail_len <= 0) {
			debug_info("[mime]: fail to get mail"
				" length in mime_read_content");
			*plength = 0;
			return FALSE;
		}
		if (mail_len > max_length) {
			*plength = 0;
			return FALSE;
		}
		pallocator = lib_buffer_init(STREAM_ALLOC_SIZE,
				mail_len / STREAM_BLOCK_SIZE + 1, FALSE);
		if (NULL == pallocator) {
			debug_info("[mime]: Failed to init lib"
				" buffer in mime_read_content");
			*plength = 0;
			return FALSE;
		}
		stream_init(&tmp_stream, pallocator);
		if (!mail_serialize(reinterpret_cast<MAIL *>(pmime->content_begin), &tmp_stream)) {
			stream_free(&tmp_stream);
			lib_buffer_free(pallocator);
			*plength = 0;
			return FALSE;
		}
		offset = 0;
		buff_size = STREAM_BLOCK_SIZE;
		while ((ptr = stream_getbuffer_for_reading(&tmp_stream, &buff_size))) {
			memcpy(out_buff + offset, ptr, buff_size);
			offset += buff_size;
			buff_size = STREAM_BLOCK_SIZE;
		}
		stream_free(&tmp_stream);
		lib_buffer_free(pallocator);
		*plength = offset;
		return TRUE;
	}
	if (FALSE == mime_get_field(pmime, "Content-Transfer-Encoding",
		encoding, 256)) {
		encoding_type = MIME_ENCODING_NONE;
	} else {
		HX_strrtrim(encoding);
		HX_strltrim(encoding);
		if (0 == strcasecmp(encoding, "base64")) {
			encoding_type = MIME_ENCODING_BASE64;
		} else if (0 == strcasecmp(encoding, "quoted-printable")) {
			encoding_type = MIME_ENCODING_QP;
		} else if (0 == strcasecmp(encoding, "uue") ||
			0 == strcasecmp(encoding, "x-uue") ||
			0 == strcasecmp(encoding, "uuencode") ||
			0 == strcasecmp(encoding, "x-uuencode")) {
			encoding_type = MIME_ENCODING_UUENCODE;
		} else {
			encoding_type = MIME_ENCODING_UNKNOWN;
		}
	}
	
	pbuff = static_cast<char *>(malloc(((pmime->content_length - 1) / (64 * 1024) + 1) * 64 * 1024));
	if (NULL == pbuff) {
		debug_info("[mime]: Failed to allocate memory in mime_read_content");
		*plength = 0;
		return FALSE;
	}
	
	/* \r\n before boundary string or end of mail should not be inclued */
	if (pmime->content_length < 2) {
		tmp_len = 1;
	} else {
		tmp_len = pmime->content_length - 2;
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
	case MIME_ENCODING_BASE64:
		if (0 != decode64_ex(pbuff, size, out_buff, max_length, plength)) {
			debug_info("[mime]: fail to decode base64 mime content");
			if (0 == *plength) {
				free(pbuff);
				return FALSE;
			}
		}
		free(pbuff);
		return TRUE;
	case MIME_ENCODING_QP:
		tmp_len = qp_decode_ex(out_buff, max_length, pbuff, size);
		if (-1 == tmp_len) {
			goto COPY_RAW_DATA;
		} else {
			*plength = tmp_len;
			free(pbuff);
			return TRUE;
		}
	case MIME_ENCODING_UUENCODE:
		if (0 != uudecode(pbuff, size, NULL, NULL, out_buff, plength)) {
			debug_info("[mime]: fail to decode uuencode mime content");
			goto COPY_RAW_DATA;
		}
		free(pbuff);
		return TRUE;
	default:
 COPY_RAW_DATA:
		if (max_length >= size) {
			memcpy(out_buff, pbuff, size);
			*plength = size;
			free(pbuff);
			return TRUE;
		} else {
			*plength = 0;
			free(pbuff);
			return FALSE;
		}
	}
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
BOOL mime_to_file(MIME *pmime, int fd)
{
	BOOL has_submime;
	MIME *pmime_child;
	size_t len, tmp_len;
	int	tag_len, val_len;
	SIMPLE_TREE_NODE *pnode;
	char tmp_buff[MIME_FIELD_LEN + MIME_NAME_LEN + 4];
	
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime]: NULL pointer found in mime_to_file");
		return FALSE;
	}
#endif
	if (NONE_MIME == pmime->mime_type) {
#ifdef _DEBUG_UMTA
		debug_info("[mime]: mime content type is not set");
#endif
		return FALSE;
	}
	if (FALSE == pmime->head_touched){
		/* the original buffer contains \r\n */
		if (pmime->head_begin + pmime->head_length
			+ 2 == pmime->content_begin) {
			if (pmime->head_length + 2 != write(fd,
				pmime->head_begin, pmime->head_length + 2)) {
				return FALSE;
			}
		} else {
			if (pmime->head_length != write(fd,
				pmime->head_begin, pmime->head_length)) {
				return FALSE;
			}
			if (2 != write(fd, "\r\n", 2)) {
				return FALSE;
			}
		}
	} else {	
		mem_file_seek(&pmime->f_other_fields,
			MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_read(&pmime->f_other_fields, 
			(char*)&tag_len, sizeof(int))) {
			/* xxxxx: yyyyy */
			mem_file_read(&pmime->f_other_fields, tmp_buff, tag_len);
			len = tag_len;
			memcpy(tmp_buff + len, ": ", 2);
			len += 2;
			mem_file_read(&pmime->f_other_fields, (char*)&val_len,
				sizeof(int));
			mem_file_read(&pmime->f_other_fields, tmp_buff + len, val_len);
			len += val_len;
			memcpy(tmp_buff + len, "\r\n", 2);
			len += 2;
			if (len != write(fd, tmp_buff, len)) {
				return FALSE;
			}
		}

		/* Content-Type: xxxxx */
		memcpy(tmp_buff, "Content-Type: ", 14);
		len = 14;
		val_len = strlen(pmime->content_type);
		memcpy(tmp_buff + len, pmime->content_type, val_len);
		len += val_len;
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		mem_file_seek(&pmime->f_type_params, MEM_FILE_READ_PTR, 0, 
			MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_read(&pmime->f_type_params, 
			(char*)&tag_len, sizeof(int))) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			if (len > MIME_FIELD_LEN + MIME_NAME_LEN - tag_len) {
				return FALSE;
			}
			memcpy(tmp_buff + len, ";\r\n\t", 4);
			len += 4;
			mem_file_read(&pmime->f_type_params, tmp_buff + len, tag_len);
			len += tag_len;
			mem_file_read(&pmime->f_type_params,
				(char*)&val_len, sizeof(int));
			if (len > MIME_FIELD_LEN + MIME_NAME_LEN + 3 - val_len) {
				return FALSE;
			}
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (0 != val_len) {
				memcpy(tmp_buff + len, "=", 1);
				len += 1;
				mem_file_read(&pmime->f_type_params, tmp_buff + len, val_len);
				len += val_len;
			}
		}
		if (len > MIME_FIELD_LEN + MIME_NAME_LEN) {
			return FALSE;
		}
		/* \r\n for separate head and content */
		memcpy(tmp_buff + len, "\r\n\r\n", 4);
		len += 4;
		if (len != write(fd, tmp_buff, len)) {
			return FALSE;
		}
		
	}
	if (SINGLE_MIME == pmime->mime_type) {
		if (NULL != pmime->content_begin) {
			if (0 != pmime->content_length) {
				if (pmime->content_length != write(fd,
					pmime->content_begin, pmime->content_length)) {
					return FALSE;
				}
			} else {
				if (!mail_to_file(reinterpret_cast<MAIL *>(pmime->content_begin), fd))
					return FALSE;
			}
		} else {
			/* if there's nothing, just append an empty line */
			if (2 != write(fd, "\r\n", 2)) {
				return FALSE;
			}
		}
	} else {
		if (NULL == pmime->first_boundary) {
			if (48 != write(fd, "This is a multi-part message "
						"in MIME format.\r\n\r\n", 48)) {
				return FALSE;
			}
		} else {
			if (pmime->first_boundary - pmime->content_begin != write(fd,
				pmime->content_begin, pmime->first_boundary - 
				pmime->content_begin)) {
				return FALSE;
			}
		}
		pnode = simple_tree_node_get_child(&pmime->node);
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
			if (len != write(fd, tmp_buff, len)) {
				return FALSE;
			}
			pmime_child = (MIME*)pnode->pdata;
			if (FALSE == mime_to_file(pmime_child, fd)) {
				return FALSE;
			}
			pnode = simple_tree_node_get_sibling(pnode);
		}
		if (FALSE == has_submime) {
			memcpy(tmp_buff, "--", 2);
			len = 2;
			memcpy(tmp_buff + len, pmime->boundary_string,
									pmime->boundary_len);
			len += pmime->boundary_len;
			memcpy(tmp_buff + len, "\r\n\r\n", 4);
			len += 4;
			if (len != write(fd, tmp_buff, len)) {
				return FALSE;
			}
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
				debug_info("[mime]: fatal error in mime_to_file");
				return FALSE;
			}
		}
		if (len != write(fd, tmp_buff, len)) {
			return FALSE;
		}
	}
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
BOOL mime_to_ssl(MIME *pmime, SSL *ssl)
{
	BOOL has_submime;
	MIME *pmime_child;
	size_t len, tmp_len;
	int tag_len, val_len;
	SIMPLE_TREE_NODE *pnode;
	char tmp_buff[MIME_FIELD_LEN + MIME_NAME_LEN + 4];
	
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime || NULL == ssl) {
		debug_info("[mime]: NULL pointer found in mime_to_ssl");
		return FALSE;
	}
#endif
	if (NONE_MIME == pmime->mime_type) {
#ifdef _DEBUG_UMTA
		debug_info("[mime]: mime content type is not set");
#endif
		return FALSE;
	}
	if (FALSE == pmime->head_touched){
		/* the original buffer contains \r\n */
		if (pmime->head_begin + pmime->head_length
			+ 2 == pmime->content_begin) {
			if (pmime->head_length + 2 != SSL_write(ssl,
				pmime->head_begin, pmime->head_length + 2)) {
				return FALSE;
			}
		} else {
			if (pmime->head_length != SSL_write(ssl,
				pmime->head_begin, pmime->head_length)) {
				return FALSE;
			}
			if (2 != SSL_write(ssl, "\r\n", 2)) {
				return FALSE;
			}
		}
	} else {	
		mem_file_seek(&pmime->f_other_fields,
			MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_read(&pmime->f_other_fields, 
			(char*)&tag_len, sizeof(int))) {
			/* xxxxx: yyyyy */
			mem_file_read(&pmime->f_other_fields, tmp_buff, tag_len);
			len = tag_len;
			memcpy(tmp_buff + len, ": ", 2);
			len += 2;
			mem_file_read(&pmime->f_other_fields, (char*)&val_len,
				sizeof(int));
			mem_file_read(&pmime->f_other_fields, tmp_buff + len, val_len);
			len += val_len;
			memcpy(tmp_buff + len, "\r\n", 2);
			len += 2;
			if (len != SSL_write(ssl, tmp_buff, len)) {
				return FALSE;
			}
		}

		/* Content-Type: xxxxx */
		memcpy(tmp_buff, "Content-Type: ", 14);
		len = 14;
		val_len = strlen(pmime->content_type);
		memcpy(tmp_buff + len, pmime->content_type, val_len);
		len += val_len;
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		mem_file_seek(&pmime->f_type_params, MEM_FILE_READ_PTR, 0, 
			MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_read(&pmime->f_type_params, 
			(char*)&tag_len, sizeof(int))) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			if (len > MIME_FIELD_LEN + MIME_NAME_LEN - tag_len) {
				return FALSE;
			}
			memcpy(tmp_buff + len, ";\r\n\t", 4);
			len += 4;
			mem_file_read(&pmime->f_type_params, tmp_buff + len, tag_len);
			len += tag_len;
			mem_file_read(&pmime->f_type_params,
				(char*)&val_len, sizeof(int));
			if (len > MIME_FIELD_LEN + MIME_NAME_LEN + 3 - val_len) {
				return FALSE;
			}
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (0 != val_len) {
				memcpy(tmp_buff + len, "=", 1);
				len += 1;
				mem_file_read(&pmime->f_type_params, tmp_buff + len, val_len);
				len += val_len;
			}
		}
		if (len > MIME_FIELD_LEN + MIME_NAME_LEN) {
			return FALSE;
		}
		/* \r\n for separate head and content */
		memcpy(tmp_buff + len, "\r\n\r\n", 4);
		len += 4;
		if (len != SSL_write(ssl, tmp_buff, len)) {
			return FALSE;
		}
		
	}
	if (SINGLE_MIME == pmime->mime_type) {
		if (NULL != pmime->content_begin) {
			if (0 != pmime->content_length) {
				if (pmime->content_length != SSL_write(ssl,
					pmime->content_begin, pmime->content_length)) {
					return FALSE;
				}
			} else {
				if (!mail_to_ssl(reinterpret_cast<MAIL *>(pmime->content_begin), ssl))
					return FALSE;
			}
		} else {
			/* if there's nothing, just append an empty line */
			if (2 != SSL_write(ssl, "\r\n", 2)) {
				return FALSE;
			}
		}
	} else {
		if (NULL == pmime->first_boundary) {
			if (48 != SSL_write(ssl, "This is a multi-part message "
				"in MIME format.\r\n\r\n", 48)) {
				return FALSE;
			}
		} else {
			if (pmime->first_boundary - pmime->content_begin != SSL_write(
				ssl, pmime->content_begin, pmime->first_boundary - 
				pmime->content_begin)) {
				return FALSE;
			}
		}
		pnode = simple_tree_node_get_child(&pmime->node);
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
			if (len != SSL_write(ssl, tmp_buff, len)) {
				return FALSE;
			}
			pmime_child = (MIME*)pnode->pdata;
			if (FALSE == mime_to_ssl(pmime_child, ssl)) {
				return FALSE;
			}
			pnode = simple_tree_node_get_sibling(pnode);
		}
		if (FALSE == has_submime) {
			memcpy(tmp_buff, "--", 2);
			len = 2;
			memcpy(tmp_buff + len, pmime->boundary_string,
									pmime->boundary_len);
			len += pmime->boundary_len;
			memcpy(tmp_buff + len, "\r\n\r\n", 4);
			len += 4;
			if (len != SSL_write(ssl, tmp_buff, len)) {
				return FALSE;
			}
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
				debug_info("[mime]: fatal error in mime_to_ssl");
				return FALSE;
			}
		}
		if (len != SSL_write(ssl, tmp_buff, len)) {
			return FALSE;
		}
	}
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
BOOL mime_check_dot(MIME *pmime)
{
	size_t	tmp_len;
	int		tag_len, val_len;
	char	tmp_buff[MIME_FIELD_LEN + MIME_NAME_LEN + 4];
	MIME	*pmime_child;
	SIMPLE_TREE_NODE *pnode;
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime]: NULL pointer found in mime_check_dot");
		return FALSE;
	}
#endif
	if (NONE_MIME == pmime->mime_type) {
#ifdef _DEBUG_UMTA
		debug_info("[mime]: mime content type is not set");
#endif
		return FALSE;
	}
	if (FALSE == pmime->head_touched) {
		if (pmime->head_length >= 2 && (('.' == pmime->head_begin[0] &&
			'.' == pmime->head_begin[1]) || NULL != memmem(
			pmime->head_begin, pmime->head_length, "\r\n..", 4))) {
			return TRUE;
		}
	} else {	
		mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, 0, 
			MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_read(&pmime->f_other_fields, 
			(char*)&tag_len, sizeof(int))) {
			/* xxxxx: yyyyy */
			mem_file_read(&pmime->f_other_fields, tmp_buff, tag_len);
			if (tag_len >= 2 && '.' == tmp_buff[0] && '.' == tmp_buff[1]) {
				return TRUE;
			}
			mem_file_read(&pmime->f_other_fields, (char*)&val_len,
				sizeof(int));
			mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, val_len,
                MEM_FILE_SEEK_CUR);
		}
		
	}
	if (SINGLE_MIME == pmime->mime_type) {
		if (NULL != pmime->content_begin) {
			if (0 != pmime->content_length) {
				if (pmime->content_length >= 2 &&
					(('.' == pmime->content_begin[0] &&
					'.' == pmime->content_begin[1]) ||
					NULL != memmem(pmime->content_begin,
					pmime->content_length, "\r\n..", 4))) {
					return TRUE;
				}
			} else {
				if (mail_check_dot(reinterpret_cast<MAIL *>(pmime->content_begin)))
					return TRUE;
			}
		} 
	} else {
		if (NULL != pmime->first_boundary) {
			tmp_len = pmime->first_boundary - pmime->content_begin;
			if (tmp_len >= 2 && (('.' == pmime->first_boundary[0] &&
				'.' == pmime->first_boundary[1]) ||
				NULL != memmem(pmime->first_boundary, tmp_len, "\r\n..", 4))) {
				return TRUE;
			}
		}
		pnode = simple_tree_node_get_child(&pmime->node);
        while (NULL != pnode) {
			pmime_child = (MIME*)pnode->pdata;
			if (TRUE == mime_check_dot(pmime_child)) {
				return TRUE;
			}
			pnode = simple_tree_node_get_sibling(pnode);
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
ssize_t mime_get_length(MIME *pmime)
{
	int		tag_len, val_len;
	size_t	mime_len, tmp_len;
	MIME	*pmime_child;
	BOOL	has_submime;
	SIMPLE_TREE_NODE *pnode;
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime]: NULL pointer found in mime_get_length");
		return -1;
	}
#endif
	if (NONE_MIME == pmime->mime_type) {
		return -1;
	}
	mime_len = 0;
	if (FALSE == pmime->head_touched){
		/* the original buffer contains \r\n */
		mime_len += pmime->head_length + 2;
	} else {	
		mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, 0, 
			MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_read(&pmime->f_other_fields, 
			(char*)&tag_len, sizeof(int))) {
			/* xxxxx: yyyyy */
			mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, tag_len,
				MEM_FILE_SEEK_CUR);
			mime_len += tag_len + 2;
			mem_file_read(&pmime->f_other_fields, (char*)&val_len,
				sizeof(int));
			mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, val_len,
				MEM_FILE_SEEK_CUR);
			mime_len += val_len + 2;
		}

		/* Content-Type: xxxxx */
		mime_len += 14;
		mime_len += strlen(pmime->content_type);
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		mem_file_seek(&pmime->f_type_params, MEM_FILE_READ_PTR, 0, 
			MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_read(&pmime->f_type_params, 
			(char*)&tag_len, sizeof(int))) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			mime_len += tag_len + 4;
			mem_file_seek(&pmime->f_type_params, MEM_FILE_READ_PTR, tag_len,
				MEM_FILE_SEEK_CUR);
			mem_file_read(&pmime->f_type_params, (char*)&val_len, 
				sizeof(int));
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (0 != val_len) {
				mime_len += val_len + 1;
				mem_file_seek(&pmime->f_type_params, MEM_FILE_READ_PTR, val_len,
					MEM_FILE_SEEK_CUR);
			}
		}
		/* \r\n for separate head and content */
		mime_len += 4;
	}
	if (SINGLE_MIME == pmime->mime_type) {
		if (NULL != pmime->content_begin) {
			if (0 != pmime->content_length) {
				mime_len += pmime->content_length;
			} else {
				auto mgl = mail_get_length(reinterpret_cast<MAIL *>(pmime->content_begin));
				if (mgl < 0)
					return -1;
				mime_len += mgl;
			}
		} else {
			/* if there's nothing, just append an empty line */
			mime_len += 2;
		}
	} else {
		if (NULL == pmime->first_boundary) {
			mime_len += 48;
		} else {
			mime_len += pmime->first_boundary - pmime->content_begin;
		}
		pnode = simple_tree_node_get_child(&pmime->node);
		has_submime = FALSE;
        while (NULL != pnode) {
			has_submime = TRUE;
			mime_len += pmime->boundary_len + 4;
			pmime_child = (MIME*)pnode->pdata;
			tmp_len = mime_get_length(pmime_child);
			if (-1 == tmp_len) {
				return -1;
			}
			mime_len += tmp_len;
			pnode = simple_tree_node_get_sibling(pnode);
		}
		if (FALSE == has_submime) {
			mime_len += pmime->boundary_len + 6;
		}
		mime_len += pmime->boundary_len + 4;
		if (NULL == pmime->last_boundary) {
			mime_len += 4;
		} else {
			tmp_len = pmime->content_length - (pmime->last_boundary - 
					  pmime->content_begin);
			if (tmp_len > 0) {
				mime_len += tmp_len;
			} else if (0 == tmp_len) {
				mime_len += 2;
			}
			
		}
	}
	return mime_len;
}

BOOL mime_get_filename(MIME *pmime, char *file_name)
{
	int i;
	int mode;
	char *ptr;
	char *pend;
	int tmp_len;
	char *pbegin;
	char encoding[256];
	
	if (TRUE == mime_get_content_param(pmime, "name", file_name, 256)) {
		goto FIND_FILENAME;
	} else if (TRUE == mime_get_field(pmime, "Content-Disposition",
		file_name, 256)) {
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
	} else if (TRUE == mime_get_field(pmime,
		"Content-Transfer-Encoding", encoding, 256)) {
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
int mime_get_mimes_digest(MIME *pmime, const char* id_string,
	size_t *poffset, int *pcount, char *pbuff, int length)
{
	int		count;
	int		tag_len, val_len;
	size_t	i, content_len;
	size_t  buff_len, tmp_len;
	size_t  head_offset;
	MIME	*pmime_child;
	BOOL	has_submime;
	SIMPLE_TREE_NODE *pnode;
	char    temp_id[64];
	char    charset_buff[32];
	char    content_type[256];
	char    encoding_buff[128];
	char    file_name[256];
	char    temp_buff[512];
	char    content_ID[128];
	char    content_location[256];
	char    content_disposition[256];
	char    *ptoken;
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime || NULL == pbuff || NULL == poffset || NULL == pcount) {
		debug_info("[mime]: NULL pointer found in mime_get_mimes_digest");
		return -1;
	}
#endif
	if (NONE_MIME == pmime->mime_type) {
		return -1;
	}
	buff_len = 0;
	head_offset = *poffset;
	if (FALSE == pmime->head_touched){
		/* the original buffer contains \r\n */
		*poffset += pmime->head_length + 2;
	} else {	
		mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, 0, 
			MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_read(&pmime->f_other_fields, 
			(char*)&tag_len, sizeof(int))) {
			/* xxxxx: yyyyy */
			mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, tag_len,
				MEM_FILE_SEEK_CUR);
			*poffset += tag_len + 2;
			mem_file_read(&pmime->f_other_fields, (char*)&val_len,
				sizeof(int));
			mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, val_len,
				MEM_FILE_SEEK_CUR);
			*poffset += val_len + 2;
		}

		/* Content-Type: xxxxx */
		*poffset += 14;
		*poffset += strlen(pmime->content_type);
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		mem_file_seek(&pmime->f_type_params, MEM_FILE_READ_PTR, 0, 
			MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_read(&pmime->f_type_params, 
			(char*)&tag_len, sizeof(int))) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			*poffset += tag_len + 4;
			mem_file_seek(&pmime->f_type_params, MEM_FILE_READ_PTR, tag_len,
				MEM_FILE_SEEK_CUR);
			mem_file_read(&pmime->f_type_params, (char*)&val_len, 
				sizeof(int));
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (0 != val_len) {
				*poffset += val_len + 1;
				mem_file_seek(&pmime->f_type_params, MEM_FILE_READ_PTR, val_len,
					MEM_FILE_SEEK_CUR);
			}
		}
		/* \r\n for separate head and content */
		*poffset += 4;
	}
	if (SINGLE_MIME == pmime->mime_type) {

		if (*pcount > 0) {
			pbuff[buff_len] = ',';
			buff_len ++;
		}
		
		strcpy(content_type, mime_get_content_type(pmime));
		if (FALSE == mime_check_ascii_printable(content_type)) {
			strcpy(content_type, "application/octet-stream");
		}
		tmp_len = strlen(content_type);
		for (i=0; i<tmp_len; i++) {
			if ('"' == content_type[i] || '\\' == content_type[i]) {
				content_type[i] = ' ';
			}
		}
		HX_strrtrim(content_type);
		HX_strltrim(content_type);
		
		if (FALSE == mime_get_field(pmime, "Content-Transfer-Encoding",
			encoding_buff, 128) || FALSE == mime_check_ascii_printable(
			encoding_buff)) {
			buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
						"{\"id\":\"%s\",\"ctype\":\"%s\","
						"\"encoding\":\"8bit\",\"head\":%zu,\"begin\":%zu,",
						id_string, content_type, head_offset, *poffset);
		} else {
			tmp_len = strlen(encoding_buff);
			for (i=0; i<tmp_len; i++) {
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
				auto mgl = mail_get_length(reinterpret_cast<MAIL *>(pmime->content_begin));
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

		if (TRUE == mime_get_content_param(pmime, "charset",
			charset_buff, 32) && TRUE == mime_check_ascii_printable(
			charset_buff)) {
			tmp_len = strlen(charset_buff);
			for (i=0; i<tmp_len; i++) {
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
		
		if (TRUE == mime_get_filename(pmime, file_name)) {
			encode64(file_name, strlen(file_name), temp_buff, 512, &tmp_len);
			buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
							",\"filename\":\"%s\"", temp_buff);
		}
		if (TRUE == mime_get_field(pmime,
			"Content-Disposition", content_disposition, 256)) {
			ptoken = strchr(content_disposition, ';');
			if (NULL != ptoken) {
				*ptoken = '\0';
			}
			HX_strrtrim(content_disposition);
			HX_strltrim(content_disposition);
			if ('\0' != content_disposition[0] &&
				TRUE == mime_check_ascii_printable(content_disposition)) {
				tmp_len = strlen(content_disposition);
				for (i=0; i<tmp_len; i++) {
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

		if (TRUE == mime_get_field(pmime, "Content-ID", content_ID, 128)) {
			tmp_len = strlen(content_ID);
			encode64(content_ID, tmp_len, temp_buff, 256, &tmp_len);
			buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
							",\"cid\":\"%s\"", temp_buff);
			if (buff_len >= length - 1) {
				return -1;
			}
		}

		if (TRUE == mime_get_field(pmime, "Content-Location",
			content_location, 256)) {
			tmp_len = strlen(content_location);
			encode64(content_location, tmp_len, temp_buff, 512, &tmp_len);
			buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
							",\"cntl\":\"%s\"", temp_buff);
			if (buff_len >= length - 1) {
				return -1;
			}
		}
		
		pbuff[buff_len] = '}';
		buff_len ++;
	} else {
		if (NULL == pmime->first_boundary) {
			*poffset += 48;
		} else {
			*poffset += pmime->first_boundary - pmime->content_begin;
		}
		pnode = simple_tree_node_get_child(&pmime->node);
		has_submime = FALSE;
		count = 1;
        while (NULL != pnode) {
			has_submime = TRUE;
			*poffset += pmime->boundary_len + 4;
			pmime_child = (MIME*)pnode->pdata;
			if ('\0' == id_string[0]) {
				snprintf(temp_id, 64, "%d", count);
			} else {
				snprintf(temp_id, 64, "%s.%d", id_string, count);
			}
			tmp_len = mime_get_mimes_digest(pmime_child, temp_id, poffset,
						pcount, pbuff + buff_len, length - buff_len);
			if (-1 == tmp_len || buff_len + tmp_len >= length - 1) {
				return -1;
			}
			buff_len += tmp_len;
			pnode = simple_tree_node_get_sibling(pnode);
			count ++;
		}
		if (FALSE == has_submime) {
			*poffset += pmime->boundary_len + 6;
		}
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
	}
	return buff_len;
}

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
int mime_get_structure_digest(MIME *pmime, const char* id_string,
	size_t *poffset, int *pcount, char *pbuff, int length)
{
	int		count;
	int		tag_len, val_len;
	size_t  i, buff_len, tmp_len;
	size_t  head_offset;
	MIME	*pmime_child;
	BOOL	has_submime;
	SIMPLE_TREE_NODE *pnode;
	char    temp_id[64];
	char    content_type[256];
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime || NULL == pbuff || NULL == poffset || NULL == pcount) {
		debug_info("[mime]: NULL pointer found in mime_get_structure_digest");
		return -1;
	}
#endif
	if (NONE_MIME == pmime->mime_type) {
		return -1;
	}
	buff_len = 0;
	head_offset = *poffset;
	if (FALSE == pmime->head_touched){
		/* the original buffer contains \r\n */
		*poffset += pmime->head_length + 2;
	} else {	
		mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, 0, 
			MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_read(&pmime->f_other_fields, 
			(char*)&tag_len, sizeof(int))) {
			/* xxxxx: yyyyy */
			mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, tag_len,
				MEM_FILE_SEEK_CUR);
			*poffset += tag_len + 2;
			mem_file_read(&pmime->f_other_fields, (char*)&val_len,
				sizeof(int));
			mem_file_seek(&pmime->f_other_fields, MEM_FILE_READ_PTR, val_len,
				MEM_FILE_SEEK_CUR);
			*poffset += val_len + 2;
		}

		/* Content-Type: xxxxx */
		*poffset += 14;
		*poffset += strlen(pmime->content_type);
		/* Content-Type: xxxxx;\r\n\tyyyyy=zzzzz */
		mem_file_seek(&pmime->f_type_params, MEM_FILE_READ_PTR, 0, 
			MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_read(&pmime->f_type_params, 
			(char*)&tag_len, sizeof(int))) {
			/* content-type: xxxxx"; \r\n\t"yyyyy */
			*poffset += tag_len + 4;
			mem_file_seek(&pmime->f_type_params, MEM_FILE_READ_PTR, tag_len,
				MEM_FILE_SEEK_CUR);
			mem_file_read(&pmime->f_type_params, (char*)&val_len, 
				sizeof(int));
			/* content_type: xxxxx; \r\n\tyyyyy=zzz */
			if (0 != val_len) {
				*poffset += val_len + 1;
				mem_file_seek(&pmime->f_type_params, MEM_FILE_READ_PTR, val_len,
					MEM_FILE_SEEK_CUR);
			}
		}
		/* \r\n for separate head and content */
		*poffset += 4;
	}
	if (SINGLE_MIME == pmime->mime_type) {
		if (NULL != pmime->content_begin) {
			if (0 != pmime->content_length) {
				*poffset += pmime->content_length;
			} else {
				auto mgl = mail_get_length(reinterpret_cast<MAIL *>(pmime->content_begin));
				if (mgl < 0)
					return -1;
				*poffset += mgl;
			}
		} else {
			/* if there's nothing, just append an empty line */
			*poffset += 2;
		}
		return 0;
	} else {
		if (*pcount > 0) {
			pbuff[buff_len] = ',';
			buff_len ++;
		}
		strcpy(content_type, mime_get_content_type(pmime));
		if (FALSE == mime_check_ascii_printable(content_type)) {
			strcpy(content_type, "multipart/mixed");
		}
		tmp_len = strlen(content_type);
		for (i=0; i<tmp_len; i++) {
			if ('"' == content_type[i] || '\\' == content_type[i]) {
				content_type[i] = ' ';
			}
		}
		HX_strrtrim(content_type);
		HX_strltrim(content_type);
		buff_len += gx_snprintf(pbuff + buff_len, length - buff_len,
						"{\"id\":\"%s\",\"ctype\":\"%s\",\"head\":%zu,"
						"\"begin\":%zu, \"length\":%zu}", id_string,
						content_type, head_offset, *poffset,
						head_offset + mime_get_length(pmime) - *poffset);
		if (buff_len >= length - 1) {
			return -1;
		}
		
		*pcount += 1;
		
		if (NULL == pmime->first_boundary) {
			*poffset += 48;
		} else {
			*poffset += pmime->first_boundary - pmime->content_begin;
		}
		pnode = simple_tree_node_get_child(&pmime->node);
		has_submime = FALSE;
		count = 1;
        while (NULL != pnode) {
			has_submime = TRUE;
			*poffset += pmime->boundary_len + 4;
			pmime_child = (MIME*)pnode->pdata;
			if ('\0' == id_string[0]) {
				snprintf(temp_id, 64, "%d", count);
			} else {
				snprintf(temp_id, 64, "%s.%d", id_string, count);
			}
			tmp_len = mime_get_structure_digest(pmime_child, temp_id, poffset,
						pcount, pbuff + buff_len, length - buff_len);
			if (-1 == tmp_len || buff_len + tmp_len >= length - 1) {
				return -1;
			}
			buff_len += tmp_len;
			pnode = simple_tree_node_get_sibling(pnode);
			count ++;
		}
		if (FALSE == has_submime) {
			*poffset += pmime->boundary_len + 6;
		}
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
}

/*
 *	get the mime type
 *  @param
 *		pmime [in]		indicate the mime object
 *	@return
 *		mime type
 */
int mime_get_type(MIME *pmime)
{
#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime]: NULL pointer found in mime_get_type");
		return NONE_MIME;
	}
#endif
	return pmime->mime_type;
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
		if ('-' == *ptr && '-' == *(ptr + 1) &&
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
	if (FALSE == b_match) {
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
	int length, depth;
	char *begin, *end, *ptr, temp;
	char temp_boundary[VALUE_LEN];
    int boundary_len;


#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime]: NULL pointer found in mime_produce_boundary");
		return;
	}
#endif
	depth = simple_tree_node_get_depth(&pmime->node);
	strcpy(pmime->boundary_string, "----=_NextPart_");
	length = sprintf(pmime->boundary_string + 15, "00%d_000%d_", 
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
    mime_set_content_param(pmime, "boundary", temp_boundary);
}

void mime_copy(MIME *pmime_src, MIME *pmime_dst)
{
	size_t buff_length;

#ifdef _DEBUG_UMTA
	if (NULL == pmime_dst || NULL == pmime_dst) {
		debug_info("[mime]: NULL pointer found in mime_copy");
		return;
	}
#endif
	mime_clear(pmime_dst);
	if (NONE_MIME == pmime_src->mime_type) {
		return;
	}
	pmime_dst->mime_type = pmime_src->mime_type;
	strcpy(pmime_dst->content_type, pmime_src->content_type);
	if (0 == pmime_src->boundary_len) {
		pmime_dst->boundary_string[0] = '\0';
		pmime_dst->boundary_len = 0;
	} else {
		strcpy(pmime_dst->boundary_string, pmime_src->boundary_string);
		pmime_dst->boundary_len = pmime_src->boundary_len;
	}
	if (SINGLE_MIME == pmime_src->mime_type &&
		NULL != pmime_src->content_begin) {
		buff_length = ((pmime_src->content_length - 1) /
					  (64 * 1024) + 1) * 64 * 1024;
		pmime_dst->content_begin = static_cast<char *>(malloc(buff_length));
    	if (NULL != pmime_dst->content_begin) {
    		memcpy(pmime_dst->content_begin, pmime_src->content_begin,
					pmime_src->content_length);
    		pmime_dst->content_length = pmime_src->content_length;
		} else {
			pmime_dst->content_length = 0;
		}
	} else {
		pmime_dst->content_begin = NULL;
		pmime_dst->content_length = 0;
	}
	mem_file_copy(&pmime_src->f_type_params, &pmime_dst->f_type_params);
	mem_file_copy(&pmime_src->f_other_fields, &pmime_dst->f_other_fields);
	pmime_dst->head_touched = TRUE;
	pmime_dst->content_touched = TRUE;
}

static BOOL mime_check_ascii_printable(const char *astring)
{
	size_t i, len;
	
	len = strlen(astring);
	
	for (i=0; i<len; i++) {
		if (astring[i] < 0x20 || astring[i] > 0x7E) {
			return FALSE;
		}
	}
	return TRUE;
}

MIME* mime_get_child(MIME *pmime)
{
	SIMPLE_TREE_NODE *pnode;
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime]: NULL pointer found in mime_get_child");
		return NULL;
	}
#endif
	pnode = simple_tree_node_get_child(&pmime->node);
	if (NULL == pnode) {
		return NULL;
	}
	return (MIME*)pnode->pdata;
}

MIME* mime_get_parent(MIME *pmime)
{
	SIMPLE_TREE_NODE *pnode;
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime]: NULL pointer found in mime_get_parent");
		return NULL;
	}
#endif
	pnode = simple_tree_node_get_parent(&pmime->node);
	if (NULL == pnode) {
		return NULL;
	}
	return (MIME*)pnode->pdata;
}

MIME *mime_get_sibling(MIME *pmime)
{
	SIMPLE_TREE_NODE *pnode;
	
#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime]: NULL pointer found in mime_get_sibling");
		return NULL;
	}
#endif
	pnode = simple_tree_node_get_sibling(&pmime->node);
	if (NULL == pnode) {
		return NULL;
	}
	return (MIME*)pnode->pdata;
}

size_t mime_get_children_num(MIME *pmime)
{
#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime]: NULL pointer found in mime_get_children_num");
		return 0;
	}
#endif
	return simple_tree_node_get_children_num(&pmime->node);
}
