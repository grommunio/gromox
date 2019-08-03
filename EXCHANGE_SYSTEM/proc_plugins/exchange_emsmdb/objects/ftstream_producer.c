#include "ftstream_producer.h"
#include "emsmdb_interface.h"
#include "endian_macro.h"
#include "common_util.h"
#include "ext_buffer.h"
#include "util.h"
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>


#define FSTREAM_SSVAL(pdata,v)					SSVAL(pdata,0,v)
#define FSTREAM_SIVAL(pdata,v)					SIVAL(pdata,0,v)

enum {
	POINT_TYPE_NORMAL_BREAK,
	POINT_TYPE_LONG_VAR,
	POINT_TYPE_WSTRING
};

typedef struct _POINT_NODE {
	DOUBLE_LIST_NODE node;
	uint8_t type;
	uint32_t offset;
} POINT_NODE;


static void ftstream_producer_try_recode_nbp(
	FTSTREAM_PRODUCER *pstream)
{
	uint32_t last_seek;
	POINT_NODE *ppoint;
	DOUBLE_LIST_NODE *pnode;
	
	pnode = double_list_get_tail(&pstream->bp_list);
	if (NULL == pnode) {
		last_seek = 0;
	} else {
		last_seek = ((POINT_NODE*)pnode->pdata)->offset;
	}
	if (pstream->offset - last_seek >=
		FTSTREAM_PRODUCER_POINT_LENGTH) {
		ppoint = malloc(sizeof(POINT_NODE));
		if (NULL == ppoint) {
			return;
		}
		ppoint->node.pdata = ppoint;
		ppoint->type = POINT_TYPE_NORMAL_BREAK;
		ppoint->offset = pstream->offset;
		double_list_append_as_tail(
			&pstream->bp_list, &ppoint->node);
	}
}

static void ftstream_producer_record_nbp(
	FTSTREAM_PRODUCER *pstream, uint32_t nbp)
{
	POINT_NODE *pbpnode;
	DOUBLE_LIST_NODE *pnode;
	
	pnode = double_list_get_tail(&pstream->bp_list);
	if (NULL == pnode || nbp > 
		((POINT_NODE*)pnode->pdata)->offset) {
		pbpnode = malloc(sizeof(POINT_NODE));
		if (NULL == pbpnode) {
			return;
		}
		pbpnode->node.pdata = pbpnode;
		pbpnode->type = POINT_TYPE_NORMAL_BREAK;
		pbpnode->offset = nbp;
		double_list_append_as_tail(
			&pstream->bp_list, &pbpnode->node);
	}
}

static void ftstream_producer_record_lvp(
	FTSTREAM_PRODUCER *pstream,
	uint32_t position, uint32_t length)
{
	POINT_NODE *pbpnode;
	DOUBLE_LIST_NODE *pnode;
	
	pnode = double_list_get_tail(&pstream->bp_list);
	if (NULL == pnode || position >
		((POINT_NODE*)pnode->pdata)->offset) {
		pbpnode = malloc(sizeof(POINT_NODE));
		if (NULL == pbpnode) {
			return;
		}
		pbpnode->node.pdata = pbpnode;
		pbpnode->type = POINT_TYPE_NORMAL_BREAK;
		pbpnode->offset = position;
		double_list_append_as_tail(
			&pstream->bp_list, &pbpnode->node);
		pnode = &pbpnode->node;
	}
	if (position + length >
		((POINT_NODE*)pnode->pdata)->offset) {
		pbpnode = malloc(sizeof(POINT_NODE));
		if (NULL == pbpnode) {
			return;
		}
		pbpnode->node.pdata = pbpnode;
		pbpnode->type = POINT_TYPE_LONG_VAR;
		pbpnode->offset = position + length;
		double_list_append_as_tail(
			&pstream->bp_list, &pbpnode->node);
	}
}

static void ftstream_producer_record_wsp(
	FTSTREAM_PRODUCER *pstream,
	uint32_t position, uint32_t length)
{
	POINT_NODE *pbpnode;
	DOUBLE_LIST_NODE *pnode;
	
	pnode = double_list_get_tail(&pstream->bp_list);
	if (NULL == pnode || position >
		((POINT_NODE*)pnode->pdata)->offset) {
		pbpnode = malloc(sizeof(POINT_NODE));
		if (NULL == pbpnode) {
			return;
		}
		pbpnode->node.pdata = pbpnode;
		pbpnode->type = POINT_TYPE_NORMAL_BREAK;
		pbpnode->offset = position;
		double_list_append_as_tail(
			&pstream->bp_list, &pbpnode->node);
		pnode = &pbpnode->node;
	}
	if (position + length >
		((POINT_NODE*)pnode->pdata)->offset) {
		pbpnode = malloc(sizeof(POINT_NODE));
		if (NULL == pbpnode) {
			return;
		}
		pbpnode->node.pdata = pbpnode;
		pbpnode->type = POINT_TYPE_WSTRING;
		pbpnode->offset = position + length;
		double_list_append_as_tail(
			&pstream->bp_list, &pbpnode->node);
	}
}

static BOOL ftstream_producer_write_internal(
	FTSTREAM_PRODUCER *pstream,
	const void *pbuff, uint32_t size)
{	
	if (size >= FTSTREAM_PRODUCER_BUFFER_LENGTH
		|| FTSTREAM_PRODUCER_BUFFER_LENGTH -
		pstream->buffer_offset < size) {
		if (-1 == pstream->fd) {
			pstream->fd = open(pstream->path,
				O_CREAT|O_RDWR|O_TRUNC, 0666);
			if (-1 == pstream->fd) {
				return FALSE;
			}
		}
		if (0 != pstream->buffer_offset &&
			pstream->buffer_offset != write(pstream->fd,
			pstream->buffer, pstream->buffer_offset)) {
			return FALSE;	
		}
		pstream->buffer_offset = 0;
		pstream->read_offset = 0;
	}
	if (size >= FTSTREAM_PRODUCER_BUFFER_LENGTH) {
		if (size != write(pstream->fd, pbuff, size)) {
			return FALSE;
		}
	} else {
		memcpy(pstream->buffer + pstream->buffer_offset, pbuff, size);
		pstream->buffer_offset += size;
	}
	pstream->offset += size;
	return TRUE;
}

static BOOL ftstream_producer_write_uint8(
	FTSTREAM_PRODUCER *pstream, uint8_t v)
{
	if (FALSE == ftstream_producer_write_internal(
		pstream, &v, sizeof(uint8_t))) {
		return FALSE;	
	}
	ftstream_producer_try_recode_nbp(pstream);
	return TRUE;
}

static BOOL ftstream_producer_write_uint16(
	FTSTREAM_PRODUCER *pstream, uint16_t v)
{
	uint16_t tmp_val;
	
	FSTREAM_SSVAL(&tmp_val, v);
	if (FALSE == ftstream_producer_write_internal(
		pstream, &tmp_val, sizeof(uint16_t))) {
		return FALSE;	
	}
	ftstream_producer_try_recode_nbp(pstream);
	return TRUE;
}

BOOL ftstream_producer_write_uint32(
	FTSTREAM_PRODUCER *pstream, uint32_t v)
{
	uint32_t tmp_val;
	
	FSTREAM_SIVAL(&tmp_val, v);
	if (FALSE == ftstream_producer_write_internal(
		pstream, &tmp_val, sizeof(uint32_t))) {
		return FALSE;
	}
	ftstream_producer_try_recode_nbp(pstream);
	return TRUE;
}

static BOOL ftstream_producer_write_uint64(
	FTSTREAM_PRODUCER *pstream, uint64_t v)
{
	uint64_t tmp_val;
	
	FSTREAM_SIVAL(&tmp_val, (v&0xFFFFFFFF));
	FSTREAM_SIVAL((void*)&tmp_val + 4, v >> 32);
	if (FALSE == ftstream_producer_write_internal(
		pstream, &tmp_val, sizeof(uint64_t))) {
		return FALSE;
	}
	ftstream_producer_try_recode_nbp(pstream);
	return TRUE;
}

static BOOL ftstream_producer_write_float(
	FTSTREAM_PRODUCER *pstream, float v)
{
	if (FALSE == ftstream_producer_write_internal(
		pstream, &v, sizeof(float))) {
		return FALSE;	
	}
	ftstream_producer_try_recode_nbp(pstream);
	return TRUE;
}

static BOOL ftstream_producer_write_double(
	FTSTREAM_PRODUCER *pstream, double v)
{
	if (FALSE == ftstream_producer_write_internal(
		pstream, &v, sizeof(double))) {
		return FALSE;	
	}
	ftstream_producer_try_recode_nbp(pstream);
	return TRUE;
}

static BOOL ftstream_producer_write_wstring(
	FTSTREAM_PRODUCER *pstream, const char *pstr)
{
	int len;
	char *pbuff;
	uint32_t position;
	
	len = 2*strlen(pstr) + 2;
	pbuff = malloc(len);
	if (NULL == pbuff) {
		return FALSE;
	}
	len = utf8_to_utf16le(pstr, pbuff, len);
	if (len < 2) {
		pbuff[0] = '\0';
		pbuff[1] = '\0';
		len = 2;
	}
	if (FALSE == ftstream_producer_write_uint32(
		pstream, len)) {
		free(pbuff);
		return FALSE;
	}
	position = pstream->offset;
	if (FALSE == ftstream_producer_write_internal(
		pstream, pbuff, len)) {
		free(pbuff);
		return FALSE;
	}
	free(pbuff);
	if (len >= FTSTREAM_PRODUCER_POINT_LENGTH) {
		ftstream_producer_record_wsp(pstream, position, len);
	} else {
		ftstream_producer_try_recode_nbp(pstream);
	}
	return TRUE;
}

static BOOL ftstream_producer_write_string(
	FTSTREAM_PRODUCER *pstream, const char *pstr)
{
	uint32_t len;
	uint32_t position;
	
	len = strlen(pstr) + 1;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, len)) {
		return FALSE;
	}
	position = pstream->offset;
	if (FALSE == ftstream_producer_write_internal(
		pstream, pstr, len)) {
		return FALSE;
	}
	if (len >= FTSTREAM_PRODUCER_POINT_LENGTH) {
		ftstream_producer_record_lvp(pstream, position, len);
	} else {
		ftstream_producer_try_recode_nbp(pstream);
	}
	return TRUE;
}

static BOOL ftstream_producer_write_guid(
	FTSTREAM_PRODUCER *pstream, const GUID *pguid)
{
	BINARY *pbin;
	
	pbin = common_util_guid_to_binary(*pguid);
	if (NULL == pbin) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_internal(
		pstream, pbin->pb, 16)) {
		return FALSE;
	}
	ftstream_producer_try_recode_nbp(pstream);
	return TRUE;
}

static BOOL ftstream_producer_write_binary(
	FTSTREAM_PRODUCER *pstream, const BINARY *pbin)
{
	uint32_t position;
	
	if (FALSE == ftstream_producer_write_uint32(
		pstream, pbin->cb)) {
		return FALSE;
	}
	position = pstream->offset;
	if (0 != pbin->cb && FALSE ==
		ftstream_producer_write_internal(
		pstream, pbin->pb, pbin->cb)) {
		return FALSE;
	}
	if (pbin->cb >= FTSTREAM_PRODUCER_POINT_LENGTH) {
		ftstream_producer_record_lvp(pstream, position, pbin->cb);
	} else {
		ftstream_producer_try_recode_nbp(pstream);
	}
	return TRUE;
}

static BOOL ftstream_producer_write_svreid(
	FTSTREAM_PRODUCER *pstream, const SVREID *psvreid)
{
	uint8_t ours;
	
	if (NULL != psvreid->pbin) {
		if (FALSE == ftstream_producer_write_uint32(
			pstream, psvreid->pbin->cb + 1)) {
			return FALSE;	
		}
		ours = 0;
		if (FALSE == ftstream_producer_write_internal(
			pstream, &ours, sizeof(uint8_t))) {
			return FALSE;
		}
		if (0 != psvreid->pbin->cb && FALSE ==
			ftstream_producer_write_internal(
			pstream, psvreid->pbin->pb, psvreid->pbin->cb)) {
			return FALSE;
		}
	} else {
		if (FALSE == ftstream_producer_write_uint32(pstream, 21)) {
			return FALSE;	
		}
		ours = 1;
		if (FALSE == ftstream_producer_write_internal(
			pstream, &ours, sizeof(uint8_t))) {
			return FALSE;
		}
		if (FALSE == ftstream_producer_write_uint64(
			pstream, psvreid->folder_id)) {
			return FALSE;
		}
		if (FALSE == ftstream_producer_write_uint64(
			pstream, psvreid->message_id)) {
			return FALSE;
		}
		if (FALSE == ftstream_producer_write_uint32(
			pstream, psvreid->instance)) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL ftstream_producer_write_propdef(
	FTSTREAM_PRODUCER *pstream,
	uint16_t proptype, uint16_t propid)
{
	uint16_t tmp_val;
	EXT_PUSH ext_push;
	char tmp_buff[1024];
	PROPERTY_NAME propname;
	
	FSTREAM_SSVAL(&tmp_val, proptype);
	if (FALSE == ftstream_producer_write_internal(
		pstream, &tmp_val, sizeof(uint16_t))) {
		return FALSE;
	}
	FSTREAM_SSVAL(&tmp_val, propid);
	if (FALSE == ftstream_producer_write_internal(
		pstream, &tmp_val, sizeof(uint16_t))) {
		return FALSE;
	}
	if (0 == (propid & 0x8000)) {
		ftstream_producer_try_recode_nbp(pstream);
		return TRUE;
	}
	if (FALSE == logon_object_get_named_propname(
		pstream->plogon, propid, &propname)) {
		return FALSE;
	}
	ext_buffer_push_init(&ext_push, tmp_buff,
			sizeof(tmp_buff), EXT_FLAG_UTF16);
	if (EXT_ERR_SUCCESS != ext_buffer_push_guid(
		&ext_push, &propname.guid)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&ext_push, propname.kind)) {
		return FALSE;
	}
	switch (propname.kind) {
	case KIND_LID:
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
			&ext_push, *propname.plid)) {
			return FALSE;
		}
		break;
	case KIND_NAME:
		if (EXT_ERR_SUCCESS != ext_buffer_push_wstring(
			&ext_push, propname.pname)) {
			return FALSE;
		}
		break;
	default:
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_internal(
		pstream, tmp_buff, ext_push.offset)) {
		return FALSE;
	}
	ftstream_producer_try_recode_nbp(pstream);
	return TRUE;
}

static BOOL ftstream_producer_write_propvalue(
	FTSTREAM_PRODUCER *pstream, TAGGED_PROPVAL *ppropval)
{
	int i;
	int len;
	char *pvalue;
	uint32_t count;
	uint16_t propid;
	uint16_t proptype;
	EMSMDB_INFO *pinfo;
	uint16_t write_type;
	
	propid = (ppropval->proptag & 0xFFFF0000) >> 16;
	proptype = ppropval->proptag & 0xFFFF;
	/* ignore PROPVAL_TYPE_SVREID */
	if (PROPVAL_TYPE_SVREID == proptype) {
		return TRUE;
	}
	if (PROP_TAG_MESSAGECLASS == ppropval->proptag) {
		proptype = PROPVAL_TYPE_STRING;
	}
	write_type = proptype;
	/* META_TAG_IDSETGIVEN, MS-OXCFXICS 3.2.5.2.1 */
	if (0x4017 == propid) {
		write_type = PROPVAL_TYPE_LONG;
	} else {
		if (PROPVAL_TYPE_STRING == proptype ||
			PROPVAL_TYPE_WSTRING == proptype) {
			if (pstream->string_option & STRING_OPTION_FORCE_UNICODE) {
				if (PROPVAL_TYPE_STRING == proptype) {
					proptype = PROPVAL_TYPE_WSTRING;
					write_type = PROPVAL_TYPE_WSTRING;
					len = 2*strlen(ppropval->pvalue) + 2;
					pvalue = common_util_alloc(len);
					if (NULL == pvalue) {
						return FALSE;
					}
					if (common_util_convert_string(TRUE,
						ppropval->pvalue, pvalue, len) <= 0) {
						*pvalue = '\0';	
					}
					ppropval->pvalue = pvalue;
				}
			} else if (pstream->string_option & STRING_OPTION_CPID) {
				if (PROPVAL_TYPE_STRING == proptype) {
					pinfo = emsmdb_interface_get_emsmdb_info();
					if (NULL == pinfo) {
						return FALSE;
					}
					write_type = 0x8000 | (uint16_t)pinfo->cpid;
				} else {
					write_type = 0x8000 | 1200;
				}
			} else if (STRING_OPTION_NONE == pstream->string_option) {
				if (PROPVAL_TYPE_WSTRING == proptype) {
					proptype = PROPVAL_TYPE_STRING;
					write_type = PROPVAL_TYPE_STRING;
					len = 2*strlen(ppropval->pvalue) + 2;
					pvalue = common_util_alloc(len);
					if (NULL == pvalue) {
						return FALSE;
					}
					if (common_util_convert_string(FALSE,
						ppropval->pvalue, pvalue, len) <= 0) {
						*pvalue = '\0';	
					}
					ppropval->pvalue = pvalue;
				}
			}
		}
	}
	if (FALSE == ftstream_producer_write_propdef(
		pstream, write_type, propid)) {
		return FALSE;
	}
	
	switch (proptype) {
	case PROPVAL_TYPE_SHORT:
		return ftstream_producer_write_uint16(pstream,
						*(uint16_t*)ppropval->pvalue);
	case PROPVAL_TYPE_ERROR:
	case PROPVAL_TYPE_LONG:
		return ftstream_producer_write_uint32(pstream,
						*(uint32_t*)ppropval->pvalue);
	case PROPVAL_TYPE_FLOAT:
		return ftstream_producer_write_float(pstream,
						*(float*)ppropval->pvalue);
	case PROPVAL_TYPE_DOUBLE:
	case PROPVAL_TYPE_FLOATINGTIME:
		return ftstream_producer_write_double(pstream,
						*(double*)ppropval->pvalue);
	case PROPVAL_TYPE_BYTE:
		return ftstream_producer_write_uint16(pstream,
						*(uint8_t*)ppropval->pvalue);
	case PROPVAL_TYPE_CURRENCY:
	case PROPVAL_TYPE_LONGLONG:
	case PROPVAL_TYPE_FILETIME:
		return ftstream_producer_write_uint64(pstream,
						*(uint64_t*)ppropval->pvalue);
	case PROPVAL_TYPE_STRING:
		return ftstream_producer_write_string(
					pstream, ppropval->pvalue);
	case PROPVAL_TYPE_WSTRING:
		return ftstream_producer_write_wstring(
					pstream, ppropval->pvalue);
	case PROPVAL_TYPE_GUID:
		return ftstream_producer_write_guid(
				pstream, ppropval->pvalue);
	/*
	case PROPVAL_TYPE_SVREID:
		return ftstream_producer_write_svreid(
					pstream, ppropval->pvalue);
	*/
	case PROPVAL_TYPE_OBJECT:
	case PROPVAL_TYPE_BINARY:
		return ftstream_producer_write_binary(
					pstream, ppropval->pvalue);
	case PROPVAL_TYPE_SHORT_ARRAY:
		count = ((SHORT_ARRAY*)ppropval->pvalue)->count;
		if (FALSE == ftstream_producer_write_uint32(
			pstream, count)) {
			return FALSE;
		}
		for (i=0; i<count; i++) {
			if (FALSE == ftstream_producer_write_uint16(pstream,
				((SHORT_ARRAY*)ppropval->pvalue)->ps[i])) {
				return FALSE;
			}
		}
		return TRUE;
	case PROPVAL_TYPE_LONG_ARRAY:
		count = ((LONG_ARRAY*)ppropval->pvalue)->count;
		if (FALSE == ftstream_producer_write_uint32(
			pstream, count)) {
			return FALSE;
		}
		for (i=0; i<count; i++) {
			if (FALSE == ftstream_producer_write_uint32(pstream,
				((LONG_ARRAY*)ppropval->pvalue)->pl[i])) {
				return FALSE;
			}
		}
		return TRUE;
	case PROPVAL_TYPE_LONGLONG_ARRAY:
		count = ((LONGLONG_ARRAY*)ppropval->pvalue)->count;
		if (FALSE == ftstream_producer_write_uint32(
			pstream, count)) {
			return FALSE;
		}
		for (i=0; i<count; i++) {
			if (FALSE == ftstream_producer_write_uint64(pstream,
				((LONGLONG_ARRAY*)ppropval->pvalue)->pll[i])) {
				return FALSE;
			}
		}
		return TRUE;
	case PROPVAL_TYPE_STRING_ARRAY:
		count = ((STRING_ARRAY*)ppropval->pvalue)->count;
		if (FALSE == ftstream_producer_write_uint32(
			pstream, count)) {
			return FALSE;
		}
		for (i=0; i<count; i++) {
			if (FALSE == ftstream_producer_write_string(pstream,
				((STRING_ARRAY*)ppropval->pvalue)->ppstr[i])) {
				return FALSE;
			}
		}
		return TRUE;
	case PROPVAL_TYPE_WSTRING_ARRAY:
		count = ((STRING_ARRAY*)ppropval->pvalue)->count;
		if (FALSE == ftstream_producer_write_uint32(
			pstream, count)) {
			return FALSE;
		}
		for (i=0; i<count; i++) {
			if (FALSE == ftstream_producer_write_wstring(pstream,
				((STRING_ARRAY*)ppropval->pvalue)->ppstr[i])) {
				return FALSE;
			}
		}
		return TRUE;
	case PROPVAL_TYPE_GUID_ARRAY:
		count = ((GUID_ARRAY*)ppropval->pvalue)->count;
		if (FALSE == ftstream_producer_write_uint32(
			pstream, count)) {
			return FALSE;
		}
		for (i=0; i<count; i++) {
			if (FALSE == ftstream_producer_write_guid(pstream,
				((GUID_ARRAY*)ppropval->pvalue)->pguid + i)) {
				return FALSE;
			}
		}
		return TRUE;
	case PROPVAL_TYPE_BINARY_ARRAY:
		count = ((BINARY_ARRAY*)ppropval->pvalue)->count;
		if (FALSE == ftstream_producer_write_uint32(
			pstream, count)) {
			return FALSE;
		}
		for (i=0; i<count; i++) {
			if (FALSE == ftstream_producer_write_binary(pstream,
				((BINARY_ARRAY*)ppropval->pvalue)->pbin + i)) {
				return FALSE;
			}
		}
		return TRUE;
	}
	return FALSE;
}

BOOL ftstream_producer_write_proplist(FTSTREAM_PRODUCER *pstream,
	const TPROPVAL_ARRAY *pproplist)
{
	int i;
	
	for (i=0; i<pproplist->count; i++) {
		if (FALSE == ftstream_producer_write_propvalue(
			pstream, pproplist->ppropval + i)) {
			return FALSE;	
		}
	}
	return TRUE;
}

BOOL ftstream_producer_write_errorinfo(
	FTSTREAM_PRODUCER *pstream, const EXTENDED_ERROR *perror)
{
	BINARY tmp_bin;
	uint32_t marker;
	EXT_PUSH ext_push;
	uint32_t aux_count;
	uint32_t aux_offset;
	
	
	/* binary length */
	if (NULL == perror->paux_bytes) {
		tmp_bin.cb = 92;
	} else {
		tmp_bin.cb = 94 + perror->paux_bytes->cb;
	}
	tmp_bin.pb = common_util_alloc(tmp_bin.cb);
	if (NULL == tmp_bin.pb) {
		return FALSE;
	}
	ext_buffer_push_init(&ext_push,
		tmp_bin.pb, tmp_bin.cb, 0);
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint16(
		&ext_push, perror->version)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint16(
		&ext_push, perror->padding)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		&ext_push, perror->errcode)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_long_term_id(
		&ext_push, &perror->folder_gid)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_long_term_id(
		&ext_push, &perror->message_gid)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
		&ext_push, perror->reserved, 24)) {
		return FALSE;
	}
	if (NULL == perror->paux_bytes) {
		aux_count = 0;
	} else {
		aux_count = perror->paux_bytes->cb;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		&ext_push, aux_count)) {
		return FALSE;
	}
	aux_offset = 88;
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		&ext_push, aux_offset)) {
		return FALSE;
	}
	if (NULL != perror->paux_bytes &&
		0 != perror->paux_bytes->cb) {
		if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(&ext_push,
			perror->paux_bytes->pb, perror->paux_bytes->cb)) {
			return FALSE;
		}
	}
	marker = FXERRORINFO;
	if (FALSE == ftstream_producer_write_uint32(pstream, marker)) {
		return FALSE;
	}
	/* 0x00000102 is the only proptag in proplist */
	if (FALSE == ftstream_producer_write_uint32(
		pstream, PROPVAL_TYPE_BINARY)) {
		return FALSE;
	}
	return ftstream_producer_write_binary(pstream, &tmp_bin);
}

static BOOL ftstream_producer_write_embeddedmessage(
	FTSTREAM_PRODUCER *pstream, BOOL b_delprop,
	const MESSAGE_CONTENT *pmessage)
{
	uint32_t marker;
	
	marker = STARTEMBED;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, marker)) {
		return FALSE;	
	}
	if (FALSE == ftstream_producer_write_messagecontent(
		pstream, b_delprop, pmessage)) {
		return FALSE;	
	}
	marker = ENDEMBED;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, marker)) {
		return FALSE;	
	}
	return TRUE;
}

BOOL ftstream_producer_write_attachmentcontent(
	FTSTREAM_PRODUCER *pstream, BOOL b_delprop,
	const ATTACHMENT_CONTENT *pattachment)
{
	if (FALSE == ftstream_producer_write_proplist(
		pstream, &pattachment->proplist)) {
		return FALSE;	
	}
	if (NULL != pattachment->pembedded) {
		if (FALSE == ftstream_producer_write_embeddedmessage(
			pstream, b_delprop, pattachment->pembedded)) {
			return FALSE;	
		}
	}
	return TRUE;
}

static BOOL ftstream_producer_write_recipient(
	FTSTREAM_PRODUCER *pstream, const TPROPVAL_ARRAY *prcpt)
{
	uint32_t marker;
	
	marker = STARTRECIP;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, marker)) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_proplist(
		pstream, prcpt)) {
		return FALSE;
	}
	marker = ENDTORECIP;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, marker)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL ftstream_producer_write_attachment(
	FTSTREAM_PRODUCER *pstream, BOOL b_delprop,
	const ATTACHMENT_CONTENT *pattachment)
{
	uint32_t marker;
	
	marker = NEWATTACH;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, marker)) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_attachmentcontent(
		pstream, b_delprop, pattachment)) {
		return FALSE;	
	}
	marker = ENDATTACH;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, marker)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL ftstream_producer_write_messagechildren(
	FTSTREAM_PRODUCER *pstream, BOOL b_delprop,
	const MESSAGE_CHILDREN *pchildren)
{
	int i;
	
	if (TRUE == b_delprop) {
		if (FALSE == ftstream_producer_write_uint32(
			pstream, META_TAG_FXDELPROP)) {
			return FALSE;
		}
		if (FALSE == ftstream_producer_write_uint32(
			pstream, PROP_TAG_MESSAGERECIPIENTS)) {
			return FALSE;
		}
	}
	if (NULL != pchildren->prcpts) {
		for (i=0; i<pchildren->prcpts->count; i++) {
			if (FALSE == ftstream_producer_write_recipient(
				pstream, pchildren->prcpts->pparray[i])) {
				return FALSE;
			}
		}
	}
	if (TRUE == b_delprop) {
		if (FALSE == ftstream_producer_write_uint32(
			pstream, META_TAG_FXDELPROP)) {
			return FALSE;
		}
		if (FALSE == ftstream_producer_write_uint32(
			pstream, PROP_TAG_MESSAGEATTACHMENTS)) {
			return FALSE;
		}
	}
	if (NULL != pchildren->pattachments) {
		for (i=0; i<pchildren->pattachments->count; i++) {
			if (FALSE == ftstream_producer_write_attachment(pstream,
				b_delprop, pchildren->pattachments->pplist[i])) {
				return FALSE;
			}
		}
	}
	return TRUE;
}

BOOL ftstream_producer_write_messagecontent(
	FTSTREAM_PRODUCER *pstream, BOOL b_delprop,
	const MESSAGE_CONTENT *pmessage)
{	
	if (FALSE == ftstream_producer_write_proplist(
		pstream, &pmessage->proplist)) {
		return FALSE;	
	}
	return ftstream_producer_write_messagechildren(
			pstream, b_delprop, &pmessage->children);
}

BOOL ftstream_producer_write_message(
	FTSTREAM_PRODUCER *pstream,
	const MESSAGE_CONTENT *pmessage)
{
	uint8_t *pbool;
	uint32_t marker;
	
	pbool = common_util_get_propvals((TPROPVAL_ARRAY*)
			&pmessage->proplist, PROP_TAG_ASSOCIATED);
	if (NULL == pbool || 0 == *pbool) {
		marker = STARTMESSAGE;
	} else {
		marker = STARTFAIMSG;
	}
	if (FALSE == ftstream_producer_write_uint32(
		pstream, marker)) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_messagecontent(
		pstream, FALSE, pmessage)) {
		return FALSE;	
	}
	marker = ENDMESSAGE;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, marker)) {
		return FALSE;
	}
	return TRUE;
}	

static BOOL ftstream_producer_write_messagechangeheader(
	FTSTREAM_PRODUCER *pstream,	const TPROPVAL_ARRAY *pheader)
{
	return ftstream_producer_write_proplist(pstream, pheader);
}

BOOL ftstream_producer_write_messagechangefull(
	FTSTREAM_PRODUCER *pstream,
	const TPROPVAL_ARRAY *pchgheader,
	MESSAGE_CONTENT *pmessage)
{
	uint32_t marker;
	
	marker = INCRSYNCCHG;
	if (FALSE == ftstream_producer_write_uint32(pstream, marker)) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_messagechangeheader(
		pstream, pchgheader)) {
		return FALSE;	
	}
	marker = INCRSYNCMESSAGE;
	if (FALSE == ftstream_producer_write_uint32(pstream, marker)) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_proplist(
		pstream, &pmessage->proplist)) {
		return FALSE;	
	}
	return ftstream_producer_write_messagechildren(
				pstream, TRUE, &pmessage->children);
}

static BOOL ftstream_producer_write_groupinfo(
	FTSTREAM_PRODUCER *pstream,
	const PROPERTY_GROUPINFO *pginfo)
{
	int i, j;
	BINARY tmp_bin;
	uint16_t propid;
	uint32_t marker;
	uint32_t offset;
	uint32_t offset1;
	uint32_t tmp_val;
	uint32_t info_len;
	EXT_PUSH ext_push;
	uint32_t name_size;
	PROPERTY_NAME propname;
	
	marker = INCRSYNCGROUPINFO;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, marker)) {
		return FALSE;
	}
	/* 0x00000102 is the only proptag in proplist */
	if (FALSE == ftstream_producer_write_uint32(
		pstream, PROPVAL_TYPE_BINARY)) {
		return FALSE;
	}
	if (FALSE == ext_buffer_push_init(
		&ext_push, NULL, 0, EXT_FLAG_UTF16)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		&ext_push, pginfo->group_id)) {
		ext_buffer_push_free(&ext_push);
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		&ext_push, pginfo->reserved)) {
		ext_buffer_push_free(&ext_push);
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		&ext_push, pginfo->count)) {
		ext_buffer_push_free(&ext_push);
		return FALSE;
	}
	for (i=0; i<pginfo->count; i++) {
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
			&ext_push, pginfo->pgroups[i].count)) {
			ext_buffer_push_free(&ext_push);
			return FALSE;
		}
		for (j=0; j<pginfo->pgroups[i].count; j++) {
			propid = (pginfo->pgroups[i].pproptag[j] & 0xFFFF0000) >> 16;
			if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
				&ext_push, pginfo->pgroups[i].pproptag[j])) {
				ext_buffer_push_free(&ext_push);
				return FALSE;
			}
			if (propid & 0x8000) {
				if (FALSE == logon_object_get_named_propname(
					pstream->plogon, propid, &propname)) {
					ext_buffer_push_free(&ext_push);
					return FALSE;
				}
				if (EXT_ERR_SUCCESS != ext_buffer_push_guid(
					&ext_push, &propname.guid)) {
					ext_buffer_push_free(&ext_push);
					return FALSE;
				}
				if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
					&ext_push, propname.kind)) {
					ext_buffer_push_free(&ext_push);
					return FALSE;
				}
				switch (propname.kind) {
				case KIND_LID:
					if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
						&ext_push, *propname.plid)) {
						ext_buffer_push_free(&ext_push);
						return FALSE;
					}
					break;
				case KIND_NAME:
					offset = ext_push.offset;
					if (EXT_ERR_SUCCESS != ext_buffer_push_advance(
						&ext_push, sizeof(uint32_t))) {
						ext_buffer_push_free(&ext_push);
						return FALSE;
					}
					if (EXT_ERR_SUCCESS != ext_buffer_push_wstring(
						&ext_push, propname.pname)) {
						ext_buffer_push_free(&ext_push);
						return FALSE;
					}
					offset1 = ext_push.offset - sizeof(uint16_t);
					name_size = offset1 - (offset + sizeof(uint32_t));
					ext_push.offset = offset;
					if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
						&ext_push, name_size)) {
						ext_buffer_push_free(&ext_push);
						return FALSE;
					}
					ext_push.offset = offset1;
					break;
				default:
					ext_buffer_push_free(&ext_push);
					return FALSE;
				}
			}
		}
	}
	tmp_bin.cb = ext_push.offset;
	tmp_bin.pb = ext_push.data;
	if (FALSE == ftstream_producer_write_binary(pstream, &tmp_bin)) {
		ext_buffer_push_free(&ext_push);
		return FALSE;
	}
	ext_buffer_push_free(&ext_push);
	return TRUE;
}

BOOL ftstream_producer_write_messagechangepartial(
	FTSTREAM_PRODUCER *pstream,
	const TPROPVAL_ARRAY *pchgheader,
	const MSGCHG_PARTIAL *pmsg)
{
	int i, j, k;
	uint32_t tag;
	
	if (FALSE == ftstream_producer_write_groupinfo(
		pstream, pmsg->pgpinfo)) {
		return FALSE;
	}
	tag = META_TAG_INCRSYNCGROUPID;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, tag)) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_uint32(
		pstream, pmsg->group_id)) {
		return FALSE;	
	}
	tag = INCRSYNCCHGPARTIAL;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, tag)) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_messagechangeheader(
		pstream, pchgheader)) {
		return FALSE;	
	}
	for (i=0; i<pmsg->count; i++) {
		tag = META_TAG_INCREMENTALSYNCMESSAGEPARTIAL;
		if (FALSE == ftstream_producer_write_uint32(
			pstream, tag)) {
			return FALSE;
		}
		if (FALSE == ftstream_producer_write_uint32(
			pstream, pmsg->pchanges[i].index)) {
			return FALSE;	
		}
		for (j=0; j<pmsg->pchanges[i].proplist.count; j++) {
			switch(pmsg->pchanges[i].proplist.ppropval[j].proptag) {
			case PROP_TAG_MESSAGERECIPIENTS:
				if (NULL == pmsg->children.prcpts) {
					break;
				}
				tag = META_TAG_FXDELPROP;
				if (FALSE == ftstream_producer_write_uint32(
					pstream, tag)) {
					return FALSE;
				}
				tag = PROP_TAG_MESSAGERECIPIENTS;
				if (FALSE == ftstream_producer_write_uint32(
					pstream, tag)) {
					return FALSE;
				}
				for (k=0; k<pmsg->children.prcpts->count; k++) {
					if (FALSE == ftstream_producer_write_recipient(
						pstream, pmsg->children.prcpts->pparray[k])) {
						return FALSE;
					}
				}
				break;
			case PROP_TAG_MESSAGEATTACHMENTS:
				if (NULL == pmsg->children.pattachments) {
					break;
				}
				tag = META_TAG_FXDELPROP;
				if (FALSE == ftstream_producer_write_uint32(
					pstream, tag)) {
					return FALSE;
				}
				tag = PROP_TAG_MESSAGEATTACHMENTS;
				if (FALSE == ftstream_producer_write_uint32(
					pstream, tag)) {
					return FALSE;
				}
				for (k=0; k<pmsg->children.pattachments->count; k++) {
					if (FALSE == ftstream_producer_write_attachment(pstream,
						TRUE, pmsg->children.pattachments->pplist[k])) {
						return FALSE;
					}
				}
				break;
			default:
				if (FALSE == ftstream_producer_write_propvalue(pstream,
					pmsg->pchanges[i].proplist.ppropval + j)) {
					return FALSE;	
				}
				break;
			}
		}
	}
	return TRUE;
}

static BOOL ftstream_producer_write_folderchange(
	FTSTREAM_PRODUCER *pstream,
	const TPROPVAL_ARRAY *pproplist)
{
	uint32_t marker;
	
	marker = INCRSYNCCHG;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, marker)) {
		return FALSE;
	}
	return ftstream_producer_write_proplist(
			pstream, pproplist);
}

BOOL ftstream_producer_write_deletions(
	FTSTREAM_PRODUCER *pstream,
	const TPROPVAL_ARRAY *pproplist)
{
	uint32_t marker;
	
	marker = INCRSYNCDEL;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, marker)) {
		return FALSE;
	}
	return ftstream_producer_write_proplist(
			pstream, pproplist);
}

BOOL ftstream_producer_write_state(
	FTSTREAM_PRODUCER *pstream,
	const TPROPVAL_ARRAY *pproplist)
{
	uint32_t marker;
	
	marker = INCRSYNCSTATEBEGIN;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, marker)) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_proplist(
		pstream, pproplist)) {
		return FALSE;
	}
	marker = INCRSYNCSTATEEND;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, marker)) {
		return FALSE;
	}
	return TRUE;
}

BOOL ftstream_producer_write_progresspermessage(
	FTSTREAM_PRODUCER *pstream,
	const PROGRESS_MESSAGE *pprogmsg)
{
	uint16_t b_fai;
	uint32_t marker;
	
	marker = INCRSYNCPROGRESSPERMSG;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, marker)) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_uint32(
		pstream, PROPVAL_TYPE_LONG)) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_uint32(
		pstream, pprogmsg->message_size)) {
		return FALSE;	
	}
	if (FALSE == ftstream_producer_write_uint32(
		pstream, PROPVAL_TYPE_BYTE)) {
		return FALSE;
	}
	if (TRUE == pprogmsg->b_fai) {
		b_fai = 1;
	} else {
		b_fai = 0;
	}
	if (FALSE == ftstream_producer_write_uint16(
		pstream, b_fai)) {
		return FALSE;
	}
	return TRUE;
}

BOOL ftstream_producer_write_progresstotal(
	FTSTREAM_PRODUCER *pstream,
	const PROGRESS_INFORMATION *pprogtotal)
{
	uint32_t length;
	uint32_t marker;
	
	marker = INCRSYNCPROGRESSMODE;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, marker)) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_uint32(
		pstream, PROPVAL_TYPE_BINARY)) {
		return FALSE;
	}
	/* binary length */
	if (FALSE == ftstream_producer_write_uint32(
		pstream, 32)) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_uint16(
		pstream, pprogtotal->version)) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_uint16(
		pstream, pprogtotal->padding1)) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_uint32(
		pstream, pprogtotal->fai_count)) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_uint64(
		pstream, pprogtotal->fai_size)) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_uint32(
		pstream, pprogtotal->normal_count)) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_uint32(
		pstream, pprogtotal->padding2)) {
		return FALSE;
	}
	return ftstream_producer_write_uint64(
			pstream, pprogtotal->normal_size);
}

BOOL ftstream_producer_write_readstatechanges(
	FTSTREAM_PRODUCER *pstream,
	const TPROPVAL_ARRAY *pproplist)
{
	uint32_t marker;
	
	marker = INCRSYNCREAD;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, marker)) {
		return FALSE;
	}
	return ftstream_producer_write_proplist(
			pstream, pproplist);
}

BOOL ftstream_producer_write_hierarchysync(
	FTSTREAM_PRODUCER *pstream,
	const FOLDER_CHANGES *pfldchgs,
	const TPROPVAL_ARRAY *pdels,
	const TPROPVAL_ARRAY *pstate)
{
	int i;
	uint32_t marker;
	
	for (i=0; i<pfldchgs->count; i++) {
		if (FALSE == ftstream_producer_write_folderchange(
			pstream, pfldchgs->pfldchgs + i)) {
			return FALSE;
		}
	}
	if (NULL != pdels) {
		if (FALSE == ftstream_producer_write_deletions(
			pstream, pdels)) {
			return FALSE;
		}
	}
	if (FALSE == ftstream_producer_write_state(
		pstream, pstate)) {
		return FALSE;
	}
	marker = INCRSYNCEND;
	if (FALSE == ftstream_producer_write_uint32(
		pstream, marker)) {
		return FALSE;
	}
	return TRUE;
}

FTSTREAM_PRODUCER* ftstream_producer_create(
	LOGON_OBJECT *plogon, uint8_t string_option)
{
	int stream_id;
	char path[256];
	DCERPC_INFO rpc_info;
	struct stat node_stat;
	FTSTREAM_PRODUCER *pstream;
	
	pstream = malloc(sizeof(FTSTREAM_PRODUCER));
	if (NULL == pstream) {
		return NULL;
	}
	stream_id = common_util_get_ftstream_id();
	rpc_info = get_rpc_info();
	sprintf(path, "%s/tmp/faststream", rpc_info.maildir);
	if (0 != stat(path, &node_stat)) {
		mkdir(pstream->path, 0777);
	} else {
		if (0 == S_ISDIR(node_stat.st_mode)) {
			remove(path);
			mkdir(path, 0777);
		}
	}
	sprintf(pstream->path, "%s/%d.%s", path, stream_id, get_host_ID());
	pstream->fd = -1;
	pstream->offset = 0;
	pstream->buffer_offset = 0;
	pstream->read_offset = 0;
	pstream->plogon = plogon;
	pstream->string_option = string_option;
	double_list_init(&pstream->bp_list);
	pstream->b_read = FALSE;
	return pstream;
}

void ftstream_producer_free(FTSTREAM_PRODUCER *pstream)
{
	DOUBLE_LIST_NODE *pnode;
	
	if (-1 != pstream->fd) {
		close(pstream->fd);
		remove(pstream->path);
	}
	while (pnode=double_list_get_from_head(&pstream->bp_list)) {
		free(pnode->pdata);
	}
	double_list_free(&pstream->bp_list);
	free(pstream);
}

int ftstream_producer_total_length(FTSTREAM_PRODUCER *pstream)
{
	return pstream->offset;
}

BOOL ftstream_producer_read_buffer(FTSTREAM_PRODUCER *pstream,
	void *pbuff, uint16_t *plen, BOOL *pb_last)
{
	POINT_NODE *ppoint;
	POINT_NODE *ppoint1;
	uint32_t cur_offset;
	DOUBLE_LIST_NODE *pnode;
	
	if (FALSE == pstream->b_read) {
		pnode = double_list_get_tail(&pstream->bp_list);
		if (NULL == pnode) {
			ftstream_producer_record_nbp(pstream, pstream->offset);
		} else {
			if (((POINT_NODE*)pnode->pdata)->offset !=
				pstream->offset) {
				ftstream_producer_record_nbp(pstream, pstream->offset);
			}
		}
		pstream->b_read = TRUE;
		if (-1 != pstream->fd) {
			if (0 != pstream->buffer_offset &&
				pstream->buffer_offset != write(pstream->fd,
				pstream->buffer, pstream->buffer_offset)) {
				return FALSE;
			}
			lseek(pstream->fd, 0, SEEK_SET);
		}
		cur_offset = 0;
	} else {
		if (-1 != pstream->fd) {
			cur_offset = lseek(pstream->fd, 0, SEEK_CUR);
		} else {
			cur_offset = pstream->read_offset;
		}
	}
	for (pnode=double_list_get_head(&pstream->bp_list); NULL!=pnode;
		pnode=double_list_get_after(&pstream->bp_list, pnode)) {
		ppoint = (POINT_NODE*)pnode->pdata;
		if (ppoint->offset - cur_offset <= *plen) {
			continue;
		}
		if (POINT_TYPE_NORMAL_BREAK == ppoint->type) {
			pnode = double_list_get_before(&pstream->bp_list, pnode);
			if (NULL == pnode) {
				return FALSE;
			}
			ppoint1 = (POINT_NODE*)pnode->pdata;
			if (ppoint1->offset < cur_offset) {
				return FALSE;
			}
			*plen = ppoint1->offset - cur_offset;
		} else if (POINT_TYPE_WSTRING == ppoint->type) {
			/* align to 2 bytes */
			pnode = double_list_get_before(&pstream->bp_list, pnode);
			if (NULL == pnode) {
				if (0 != (*plen)%2) {
					(*plen) --;
				}
			} else {
				ppoint1 = (POINT_NODE*)pnode->pdata;
				if (0 != (*plen - (ppoint1->offset - cur_offset))%2) {
					(*plen) --;
				}
			}
		}
		while (pnode=double_list_get_from_head(&pstream->bp_list)) {
			if (pnode->pdata == ppoint) {
				double_list_insert_as_head(&pstream->bp_list, pnode);
				break;
			}
			free(pnode->pdata);
		}
		if (-1 != pstream->fd) {
			if (*plen != read(pstream->fd, pbuff, *plen)) {
				return FALSE;
			}
		} else {
			memcpy(pbuff, pstream->buffer + pstream->read_offset, *plen);
			pstream->read_offset += *plen;
		}
		*pb_last = FALSE;
		return TRUE;
	}
	pnode = double_list_get_tail(&pstream->bp_list);
	if (NULL == pnode) {
		return FALSE;
	}
	ppoint = (POINT_NODE*)pnode->pdata;
	if (ppoint->offset < cur_offset) {
		return FALSE;
	}
	*plen = ppoint->offset - cur_offset;
	while (pnode=double_list_get_from_head(&pstream->bp_list)) {
		free(pnode->pdata);
	}
	if (-1 != pstream->fd) {
		if (*plen != read(pstream->fd, pbuff, *plen)) {
			return FALSE;
		}
	} else {
		memcpy(pbuff, pstream->buffer + pstream->read_offset, *plen);
		pstream->read_offset += *plen;
	}
	*pb_last = TRUE;
	if (-1 != pstream->fd) {
		close(pstream->fd);
		pstream->fd = -1;
		remove(pstream->path);
	}
	pstream->offset = 0;
	pstream->buffer_offset = 0;
	pstream->read_offset = 0;
	pstream->b_read = FALSE;
	return TRUE;
}
