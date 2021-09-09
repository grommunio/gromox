// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstdint>
#include <memory>
#include <string>
#include <gromox/mapidefs.h>
#include "ftstream_producer.h"
#include "emsmdb_interface.h"
#include "common_util.h"
#include <gromox/ext_buffer.hpp>
#include <gromox/util.hpp>
#include <sys/stat.h>
#include <cstring>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <cstdio>

using namespace std::string_literals;

enum {
	POINT_TYPE_NORMAL_BREAK,
	POINT_TYPE_LONG_VAR,
	POINT_TYPE_WSTRING
};

namespace {

struct POINT_NODE {
	DOUBLE_LIST_NODE node;
	uint8_t type;
	uint32_t offset;
};

}

static void ftstream_producer_try_recode_nbp(
	FTSTREAM_PRODUCER *pstream)
{
	POINT_NODE *ppoint;
	DOUBLE_LIST_NODE *pnode;
	
	pnode = double_list_get_tail(&pstream->bp_list);
	uint32_t last_seek = pnode == nullptr ? 0 : static_cast<POINT_NODE *>(pnode->pdata)->offset;
	if (pstream->offset - last_seek >=
		FTSTREAM_PRODUCER_POINT_LENGTH) {
		ppoint = me_alloc<POINT_NODE>();
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
		pbpnode = me_alloc<POINT_NODE>();
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
		pbpnode = me_alloc<POINT_NODE>();
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
		pbpnode = me_alloc<POINT_NODE>();
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
		pbpnode = me_alloc<POINT_NODE>();
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
		pbpnode = me_alloc<POINT_NODE>();
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
			pstream->fd = open(pstream->path.c_str(),
				O_CREAT|O_RDWR|O_TRUNC, 0666);
			if (-1 == pstream->fd) {
				fprintf(stderr, "E-1338: open %s: %s\n",
				        pstream->path.c_str(), strerror(errno));
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

static BOOL ftstream_producer_write_uint16(
	FTSTREAM_PRODUCER *pstream, uint16_t v)
{
	v = cpu_to_le16(v);
	if (!ftstream_producer_write_internal(pstream, &v, sizeof(v)))
		return FALSE;	
	ftstream_producer_try_recode_nbp(pstream);
	return TRUE;
}

BOOL ftstream_producer::write_uint32(uint32_t v)
{
	auto pstream = this;
	v = cpu_to_le32(v);
	if (!ftstream_producer_write_internal(pstream, &v, sizeof(v)))
		return FALSE;
	ftstream_producer_try_recode_nbp(pstream);
	return TRUE;
}

static BOOL ftstream_producer_write_uint64(
	FTSTREAM_PRODUCER *pstream, uint64_t v)
{
	v = cpu_to_le64(v);
	if (!ftstream_producer_write_internal(pstream, &v, sizeof(v)))
		return FALSE;
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
	uint32_t position;
	
	len = 2*strlen(pstr) + 2;
	auto pbuff = me_alloc<char>(len);
	if (NULL == pbuff) {
		return FALSE;
	}
	len = utf8_to_utf16le(pstr, pbuff, len);
	if (len < 2) {
		pbuff[0] = '\0';
		pbuff[1] = '\0';
		len = 2;
	}
	if (!pstream->write_uint32(len)) {
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
	if (!pstream->write_uint32(len))
		return FALSE;
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
	
	if (!pstream->write_uint32(pbin->cb))
		return FALSE;
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

static BOOL ftstream_producer_write_propdef(
	FTSTREAM_PRODUCER *pstream,
	uint16_t proptype, uint16_t propid)
{
	uint16_t tmp_val;
	EXT_PUSH ext_push;
	char tmp_buff[1024];
	PROPERTY_NAME propname;
	
	tmp_val = cpu_to_le16(proptype);
	if (FALSE == ftstream_producer_write_internal(
		pstream, &tmp_val, sizeof(uint16_t))) {
		return FALSE;
	}
	tmp_val = cpu_to_le16(propid);
	if (FALSE == ftstream_producer_write_internal(
		pstream, &tmp_val, sizeof(uint16_t))) {
		return FALSE;
	}
	if (propid == PROP_ID_INVALID)
		fprintf(stderr, "W-1271: ftstream with PROP_ID_INVALID seen\n");
	if (!is_nameprop_id(propid)) {
		ftstream_producer_try_recode_nbp(pstream);
		return TRUE;
	}
	if (!pstream->plogon->get_named_propname(propid, &propname))
		return FALSE;
	if (!ext_push.init(tmp_buff, sizeof(tmp_buff), EXT_FLAG_UTF16) ||
	    ext_push.p_guid(&propname.guid) != EXT_ERR_SUCCESS ||
	    ext_push.p_uint8(propname.kind) != EXT_ERR_SUCCESS)
		return FALSE;
	switch (propname.kind) {
	case MNID_ID:
		if (ext_push.p_uint32(propname.lid) != EXT_ERR_SUCCESS)
			return FALSE;
		break;
	case MNID_STRING:
		if (ext_push.p_wstr(propname.pname) != EXT_ERR_SUCCESS)
			return FALSE;
		break;
	default:
		return FALSE;
	}
	if (!ftstream_producer_write_internal(pstream, tmp_buff, ext_push.m_offset))
		return FALSE;
	ftstream_producer_try_recode_nbp(pstream);
	return TRUE;
}

static BOOL ftstream_producer_write_propvalue(
	FTSTREAM_PRODUCER *pstream, TAGGED_PROPVAL *ppropval)
{
	char *pvalue;
	uint32_t count;
	uint16_t propid;
	uint16_t proptype;
	uint16_t write_type;
	
	propid = PROP_ID(ppropval->proptag);
	proptype = PROP_TYPE(ppropval->proptag);
	/* ignore PT_SVREID */
	if (proptype == PT_SVREID)
		return TRUE;
	if (PROP_TAG_MESSAGECLASS == ppropval->proptag) {
		proptype = PT_STRING8;
	}
	write_type = proptype;
	/* META_TAG_IDSETGIVEN, MS-OXCFXICS 3.2.5.2.1 */
	if (0x4017 == propid) {
		write_type = PT_LONG;
	} else {
		if (proptype == PT_STRING8 || proptype == PT_UNICODE) {
			if (pstream->string_option & STRING_OPTION_FORCE_UNICODE) {
				if (proptype == PT_STRING8) {
					proptype = PT_UNICODE;
					write_type = PT_UNICODE;
					auto len = 2 * strlen(static_cast<char *>(ppropval->pvalue)) + 2;
					pvalue = cu_alloc<char>(len);
					if (NULL == pvalue) {
						return FALSE;
					}
					if (common_util_convert_string(TRUE,
					    static_cast<char *>(ppropval->pvalue), pvalue, len) <= 0)
						*pvalue = '\0';	
					ppropval->pvalue = pvalue;
				}
			} else if (pstream->string_option & STRING_OPTION_CPID) {
				if (proptype == PT_STRING8) {
					auto pinfo = emsmdb_interface_get_emsmdb_info();
					if (NULL == pinfo) {
						return FALSE;
					}
					write_type = 0x8000 | (uint16_t)pinfo->cpid;
				} else {
					write_type = 0x8000 | 1200;
				}
			} else if (STRING_OPTION_NONE == pstream->string_option) {
				if (proptype == PT_UNICODE) {
					proptype = PT_STRING8;
					write_type = PT_STRING8;
					auto len = 2 * strlen(static_cast<char *>(ppropval->pvalue)) + 2;
					pvalue = cu_alloc<char>(len);
					if (NULL == pvalue) {
						return FALSE;
					}
					if (common_util_convert_string(FALSE,
					    static_cast<char *>(ppropval->pvalue), pvalue, len) <= 0)
						*pvalue = '\0';	
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
	case PT_SHORT:
		return ftstream_producer_write_uint16(pstream,
						*(uint16_t*)ppropval->pvalue);
	case PT_ERROR:
	case PT_LONG:
		return pstream->write_uint32(*static_cast<uint32_t *>(ppropval->pvalue));
	case PT_FLOAT:
		return ftstream_producer_write_float(pstream,
						*(float*)ppropval->pvalue);
	case PT_DOUBLE:
	case PT_APPTIME:
		return ftstream_producer_write_double(pstream,
						*(double*)ppropval->pvalue);
	case PT_BOOLEAN:
		return ftstream_producer_write_uint16(pstream,
						*(uint8_t*)ppropval->pvalue);
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME:
		return ftstream_producer_write_uint64(pstream,
						*(uint64_t*)ppropval->pvalue);
	case PT_STRING8:
		return ftstream_producer_write_string(pstream, static_cast<char *>(ppropval->pvalue));
	case PT_UNICODE:
		return ftstream_producer_write_wstring(pstream, static_cast<char *>(ppropval->pvalue));
	case PT_CLSID:
		return ftstream_producer_write_guid(pstream, static_cast<GUID *>(ppropval->pvalue));
	/*
	case PT_SVREID:
		return ftstream_producer_write_svreid(
					pstream, ppropval->pvalue);
	*/
	case PT_OBJECT:
	case PT_BINARY:
		return ftstream_producer_write_binary(pstream, static_cast<BINARY *>(ppropval->pvalue));
	case PT_MV_SHORT:
		count = ((SHORT_ARRAY*)ppropval->pvalue)->count;
		if (!pstream->write_uint32(count))
			return FALSE;
		for (size_t i = 0; i < count; ++i) {
			if (FALSE == ftstream_producer_write_uint16(pstream,
				((SHORT_ARRAY*)ppropval->pvalue)->ps[i])) {
				return FALSE;
			}
		}
		return TRUE;
	case PT_MV_LONG:
		count = ((LONG_ARRAY*)ppropval->pvalue)->count;
		if (!pstream->write_uint32(count))
			return FALSE;
		for (size_t i = 0; i < count; ++i) {
			if (!pstream->write_uint32(static_cast<LONG_ARRAY *>(ppropval->pvalue)->pl[i]))
				return FALSE;
		}
		return TRUE;
	case PT_MV_I8:
		count = ((LONGLONG_ARRAY*)ppropval->pvalue)->count;
		if (!pstream->write_uint32(count))
			return FALSE;
		for (size_t i = 0; i < count; ++i) {
			if (FALSE == ftstream_producer_write_uint64(pstream,
				((LONGLONG_ARRAY*)ppropval->pvalue)->pll[i])) {
				return FALSE;
			}
		}
		return TRUE;
	case PT_MV_STRING8:
		count = ((STRING_ARRAY*)ppropval->pvalue)->count;
		if (!pstream->write_uint32(count))
			return FALSE;
		for (size_t i = 0; i < count; ++i) {
			if (FALSE == ftstream_producer_write_string(pstream,
				((STRING_ARRAY*)ppropval->pvalue)->ppstr[i])) {
				return FALSE;
			}
		}
		return TRUE;
	case PT_MV_UNICODE:
		count = ((STRING_ARRAY*)ppropval->pvalue)->count;
		if (!pstream->write_uint32(count))
			return FALSE;
		for (size_t i = 0; i < count; ++i) {
			if (FALSE == ftstream_producer_write_wstring(pstream,
				((STRING_ARRAY*)ppropval->pvalue)->ppstr[i])) {
				return FALSE;
			}
		}
		return TRUE;
	case PT_MV_CLSID:
		count = ((GUID_ARRAY*)ppropval->pvalue)->count;
		if (!pstream->write_uint32(count))
			return FALSE;
		for (size_t i = 0; i < count; ++i) {
			if (FALSE == ftstream_producer_write_guid(pstream,
				((GUID_ARRAY*)ppropval->pvalue)->pguid + i)) {
				return FALSE;
			}
		}
		return TRUE;
	case PT_MV_BINARY:
		count = ((BINARY_ARRAY*)ppropval->pvalue)->count;
		if (!pstream->write_uint32(count))
			return FALSE;
		for (size_t i = 0; i < count; ++i) {
			if (FALSE == ftstream_producer_write_binary(pstream,
				((BINARY_ARRAY*)ppropval->pvalue)->pbin + i)) {
				return FALSE;
			}
		}
		return TRUE;
	}
	return FALSE;
}

BOOL ftstream_producer::write_proplist(const TPROPVAL_ARRAY *pproplist)
{
	auto pstream = this;
	int i;
	
	for (i=0; i<pproplist->count; i++) {
		if (FALSE == ftstream_producer_write_propvalue(
			pstream, pproplist->ppropval + i)) {
			return FALSE;	
		}
	}
	return TRUE;
}

static BOOL ftstream_producer_write_embeddedmessage(
	FTSTREAM_PRODUCER *pstream, BOOL b_delprop,
	const MESSAGE_CONTENT *pmessage)
{
	if (!pstream->write_uint32(STARTEMBED))
		return FALSE;	
	if (!pstream->write_messagecontent(b_delprop, pmessage))
		return FALSE;	
	if (!pstream->write_uint32(ENDEMBED))
		return FALSE;	
	return TRUE;
}

BOOL ftstream_producer::write_attachmentcontent(BOOL b_delprop,
	const ATTACHMENT_CONTENT *pattachment)
{
	auto pstream = this;
	if (!write_proplist(&pattachment->proplist))
		return FALSE;	
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
	if (!pstream->write_uint32(STARTRECIP))
		return FALSE;
	if (!pstream->write_proplist(prcpt))
		return FALSE;
	if (!pstream->write_uint32(ENDTORECIP))
		return FALSE;
	return TRUE;
}

static BOOL ftstream_producer_write_attachment(
	FTSTREAM_PRODUCER *pstream, BOOL b_delprop,
	const ATTACHMENT_CONTENT *pattachment)
{
	if (!pstream->write_uint32(NEWATTACH))
		return FALSE;
	if (!pstream->write_attachmentcontent(b_delprop, pattachment))
		return FALSE;	
	if (!pstream->write_uint32(ENDATTACH))
		return FALSE;
	return TRUE;
}

static BOOL ftstream_producer_write_messagechildren(
	FTSTREAM_PRODUCER *pstream, BOOL b_delprop,
	const MESSAGE_CHILDREN *pchildren)
{
	if (TRUE == b_delprop) {
		if (!pstream->write_uint32(META_TAG_FXDELPROP))
			return FALSE;
		if (!pstream->write_uint32(PR_MESSAGE_RECIPIENTS))
			return FALSE;
	}
	if (NULL != pchildren->prcpts) {
		for (size_t i = 0; i < pchildren->prcpts->count; ++i) {
			if (FALSE == ftstream_producer_write_recipient(
				pstream, pchildren->prcpts->pparray[i])) {
				return FALSE;
			}
		}
	}
	if (TRUE == b_delprop) {
		if (!pstream->write_uint32(META_TAG_FXDELPROP))
			return FALSE;
		if (!pstream->write_uint32(PR_MESSAGE_ATTACHMENTS))
			return FALSE;
	}
	if (NULL != pchildren->pattachments) {
		for (size_t i = 0; i < pchildren->pattachments->count; ++i) {
			if (FALSE == ftstream_producer_write_attachment(pstream,
				b_delprop, pchildren->pattachments->pplist[i])) {
				return FALSE;
			}
		}
	}
	return TRUE;
}

BOOL ftstream_producer::write_messagecontent(BOOL b_delprop,
	const MESSAGE_CONTENT *pmessage)
{	
	auto pstream = this;
	if (!write_proplist(&pmessage->proplist))
		return FALSE;	
	return ftstream_producer_write_messagechildren(
			pstream, b_delprop, &pmessage->children);
}

BOOL ftstream_producer::write_message(const MESSAGE_CONTENT *pmessage)
{
	auto pbool = static_cast<uint8_t *>(common_util_get_propvals(&pmessage->proplist, PR_ASSOCIATED));
	uint32_t marker = pbool == nullptr || *pbool == 0 ? STARTMESSAGE : STARTFAIMSG;
	if (!write_uint32(marker))
		return FALSE;
	if (!write_messagecontent(false, pmessage))
		return FALSE;	
	if (!write_uint32(ENDMESSAGE))
		return FALSE;
	return TRUE;
}	

static BOOL ftstream_producer_write_messagechangeheader(
	FTSTREAM_PRODUCER *pstream,	const TPROPVAL_ARRAY *pheader)
{
	return pstream->write_proplist(pheader);
}

BOOL ftstream_producer::write_messagechangefull(
	const TPROPVAL_ARRAY *pchgheader,
	MESSAGE_CONTENT *pmessage)
{
	auto pstream = this;
	if (!write_uint32(INCRSYNCCHG))
		return FALSE;
	if (FALSE == ftstream_producer_write_messagechangeheader(
		pstream, pchgheader)) {
		return FALSE;	
	}
	if (!write_uint32(INCRSYNCMESSAGE))
		return FALSE;
	if (!write_proplist(&pmessage->proplist))
		return FALSE;	
	return ftstream_producer_write_messagechildren(
				pstream, TRUE, &pmessage->children);
}

static BOOL ftstream_producer_write_groupinfo(
	FTSTREAM_PRODUCER *pstream,
	const PROPERTY_GROUPINFO *pginfo)
{
	uint16_t propid;
	EXT_PUSH ext_push;
	uint32_t name_size;
	PROPERTY_NAME propname;
	
	if (!pstream->write_uint32(INCRSYNCGROUPINFO))
		return FALSE;
	/* 0x00000102 is the only proptag in proplist */
	if (!pstream->write_uint32(PT_BINARY) ||
	    !ext_push.init(nullptr, 0, EXT_FLAG_UTF16) ||
	    ext_push.p_uint32(pginfo->group_id) != EXT_ERR_SUCCESS ||
	    ext_push.p_uint32(pginfo->reserved) != EXT_ERR_SUCCESS ||
	    ext_push.p_uint32(pginfo->count) != EXT_ERR_SUCCESS)
		return FALSE;
	for (size_t i = 0; i < pginfo->count; ++i) {
		if (ext_push.p_uint32(pginfo->pgroups[i].count) != EXT_ERR_SUCCESS)
			return FALSE;
		for (size_t j = 0; j < pginfo->pgroups[i].count; ++j) {
			propid = PROP_ID(pginfo->pgroups[i].pproptag[j]);
			if (ext_push.p_uint32(pginfo->pgroups[i].pproptag[j]) != EXT_ERR_SUCCESS)
				return FALSE;
			if (!is_nameprop_id(propid))
				continue;
			if (!pstream->plogon->get_named_propname(propid, &propname))
				return FALSE;
			if (ext_push.p_guid(&propname.guid) != EXT_ERR_SUCCESS ||
			    ext_push.p_uint32(propname.kind) != EXT_ERR_SUCCESS)
				return FALSE;
			switch (propname.kind) {
			case MNID_ID:
				if (ext_push.p_uint32(propname.lid) != EXT_ERR_SUCCESS)
					return FALSE;
				break;
			case MNID_STRING: {
				uint32_t offset = ext_push.m_offset;
				if (ext_push.advance(sizeof(uint32_t)) != EXT_ERR_SUCCESS ||
				    ext_push.p_wstr(propname.pname) != EXT_ERR_SUCCESS)
					return FALSE;
				uint32_t offset1 = ext_push.m_offset - sizeof(uint16_t);
				name_size = offset1 - (offset + sizeof(uint32_t));
				ext_push.m_offset = offset;
				if (ext_push.p_uint32(name_size) != EXT_ERR_SUCCESS)
					return FALSE;
				ext_push.m_offset = offset1;
				break;
			}
			default:
				return FALSE;
			}
		}
	}
	BINARY tmp_bin;
	tmp_bin.cb = ext_push.m_offset;
	tmp_bin.pb = ext_push.m_udata;
	return ftstream_producer_write_binary(pstream, &tmp_bin);
}

BOOL ftstream_producer::write_messagechangepartial(
	const TPROPVAL_ARRAY *pchgheader,
	const MSGCHG_PARTIAL *pmsg)
{
	auto pstream = this;
	
	if (FALSE == ftstream_producer_write_groupinfo(
		pstream, pmsg->pgpinfo)) {
		return FALSE;
	}
	if (!write_uint32(META_TAG_INCRSYNCGROUPID))
		return FALSE;
	if (!write_uint32(pmsg->group_id))
		return FALSE;	
	if (!write_uint32(INCRSYNCCHGPARTIAL))
		return FALSE;
	if (FALSE == ftstream_producer_write_messagechangeheader(
		pstream, pchgheader)) {
		return FALSE;	
	}
	for (size_t i = 0; i < pmsg->count; ++i) {
		if (!write_uint32(META_TAG_INCREMENTALSYNCMESSAGEPARTIAL))
			return FALSE;
		if (!write_uint32(pmsg->pchanges[i].index))
			return FALSE;	
		for (size_t j = 0; j < pmsg->pchanges[i].proplist.count; ++j) {
			switch(pmsg->pchanges[i].proplist.ppropval[j].proptag) {
			case PR_MESSAGE_RECIPIENTS:
				if (NULL == pmsg->children.prcpts) {
					break;
				}
				if (!write_uint32(META_TAG_FXDELPROP))
					return FALSE;
				if (!write_uint32(PR_MESSAGE_RECIPIENTS))
					return FALSE;
				for (size_t k = 0; k < pmsg->children.prcpts->count; ++k) {
					if (FALSE == ftstream_producer_write_recipient(
						pstream, pmsg->children.prcpts->pparray[k])) {
						return FALSE;
					}
				}
				break;
			case PR_MESSAGE_ATTACHMENTS:
				if (NULL == pmsg->children.pattachments) {
					break;
				}
				if (!write_uint32(META_TAG_FXDELPROP))
					return FALSE;
				if (!write_uint32(PR_MESSAGE_ATTACHMENTS))
					return FALSE;
				for (size_t k = 0; k < pmsg->children.pattachments->count; ++k) {
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
	if (!pstream->write_uint32(INCRSYNCCHG))
		return FALSE;
	return pstream->write_proplist(pproplist);
}

BOOL ftstream_producer::write_deletions(const TPROPVAL_ARRAY *pproplist)
{
	if (!write_uint32(INCRSYNCDEL))
		return FALSE;
	return write_proplist(pproplist);
}

BOOL ftstream_producer::write_state(const TPROPVAL_ARRAY *pproplist)
{
	if (!write_uint32(INCRSYNCSTATEBEGIN))
		return FALSE;
	if (!write_proplist(pproplist))
		return FALSE;
	if (!write_uint32(INCRSYNCSTATEEND))
		return FALSE;
	return TRUE;
}

BOOL ftstream_producer::write_progresspermessage(const PROGRESS_MESSAGE *pprogmsg)
{
	auto pstream = this;
	if (!write_uint32(INCRSYNCPROGRESSPERMSG))
		return FALSE;
	if (!write_uint32(PT_LONG))
		return FALSE;
	if (!write_uint32(pprogmsg->message_size))
		return FALSE;	
	if (!write_uint32(PT_BOOLEAN))
		return FALSE;
	uint16_t b_fai = !!pprogmsg->b_fai;
	if (FALSE == ftstream_producer_write_uint16(
		pstream, b_fai)) {
		return FALSE;
	}
	return TRUE;
}

BOOL ftstream_producer::write_progresstotal(const PROGRESS_INFORMATION *pprogtotal)
{
	auto pstream = this;
	if (!write_uint32(INCRSYNCPROGRESSMODE))
		return FALSE;
	if (!write_uint32(PT_BINARY))
		return FALSE;
	/* binary length */
	if (!write_uint32(32))
		return FALSE;
	if (FALSE == ftstream_producer_write_uint16(
		pstream, pprogtotal->version)) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_uint16(
		pstream, pprogtotal->padding1)) {
		return FALSE;
	}
	if (!write_uint32(pprogtotal->fai_count))
		return FALSE;
	if (FALSE == ftstream_producer_write_uint64(
		pstream, pprogtotal->fai_size)) {
		return FALSE;
	}
	if (!write_uint32(pprogtotal->normal_count))
		return FALSE;
	if (!write_uint32(pprogtotal->padding2))
		return FALSE;
	return ftstream_producer_write_uint64(
			pstream, pprogtotal->normal_size);
}

BOOL ftstream_producer::write_readstatechanges(const TPROPVAL_ARRAY *pproplist)
{
	if (!write_uint32(INCRSYNCREAD))
		return FALSE;
	return write_proplist(pproplist);
}

BOOL ftstream_producer::write_hierarchysync(
	const FOLDER_CHANGES *pfldchgs,
	const TPROPVAL_ARRAY *pdels,
	const TPROPVAL_ARRAY *pstate)
{
	auto pstream = this;
	for (size_t i = 0; i < pfldchgs->count; ++i) {
		if (FALSE == ftstream_producer_write_folderchange(
			pstream, pfldchgs->pfldchgs + i)) {
			return FALSE;
		}
	}
	if (pdels != nullptr && !write_deletions(pdels))
		return FALSE;
	if (!write_state(pstate))
		return FALSE;
	if (!write_uint32(INCRSYNCEND))
		return FALSE;
	return TRUE;
}

std::unique_ptr<FTSTREAM_PRODUCER>
ftstream_producer_create(LOGON_OBJECT *plogon, uint8_t string_option) try
{
	int stream_id;
	
	stream_id = common_util_get_ftstream_id();
	auto rpc_info = get_rpc_info();
	auto path = rpc_info.maildir + "/tmp"s;
	if (mkdir(path.c_str(), 0777) < 0 && errno != EEXIST) {
		fprintf(stderr, "E-1422: mkdir %s: %s\n", path.c_str(), strerror(errno));
		return nullptr;
	}
	path = rpc_info.maildir + "/tmp/faststream"s;
	if (mkdir(path.c_str(), 0777) < 0 && errno != EEXIST) {
		fprintf(stderr, "E-1341: mkdir %s: %s\n", path.c_str(), strerror(errno));
		return nullptr;
	}
	auto pstream = std::make_unique<FTSTREAM_PRODUCER>();
	pstream->path = path + "/"s + std::to_string(stream_id) + "." + get_host_ID();
	pstream->fd = -1;
	pstream->offset = 0;
	pstream->buffer_offset = 0;
	pstream->read_offset = 0;
	pstream->plogon = plogon;
	pstream->string_option = string_option;
	double_list_init(&pstream->bp_list);
	pstream->b_read = FALSE;
	return pstream;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1452: ENOMEM\n");
	return nullptr;
}

FTSTREAM_PRODUCER::~FTSTREAM_PRODUCER()
{
	auto pstream = this;
	DOUBLE_LIST_NODE *pnode;
	
	if (-1 != pstream->fd) {
		close(pstream->fd);
		if (remove(pstream->path.c_str()) < 0 && errno != ENOENT)
			fprintf(stderr, "W-1371: remove %s: %s\n", pstream->path.c_str(), strerror(errno));
	}
	while ((pnode = double_list_pop_front(&pstream->bp_list)) != nullptr)
		free(pnode->pdata);
	double_list_free(&pstream->bp_list);
}

BOOL ftstream_producer::read_buffer(void *pbuff, uint16_t *plen, BOOL *pb_last)
{
	auto pstream = this;
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
		cur_offset = pstream->fd != -1 ? lseek(pstream->fd, 0, SEEK_CUR) : pstream->read_offset;
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
		while ((pnode = double_list_pop_front(&pstream->bp_list)) != nullptr) {
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
	while ((pnode = double_list_pop_front(&pstream->bp_list)) != nullptr)
		free(pnode->pdata);
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
		if (remove(pstream->path.c_str()) < 0 && errno != ENOENT)
			fprintf(stderr, "W-1340: remove: %s: %s\n",
			        pstream->path.c_str(), strerror(errno));
	}
	pstream->offset = 0;
	pstream->buffer_offset = 0;
	pstream->read_offset = 0;
	pstream->b_read = FALSE;
	return TRUE;
}
