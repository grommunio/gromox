// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <string>
#include <unistd.h>
#include <sys/stat.h>
#include <gromox/element_data.hpp>
#include <gromox/endian.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/paths.h>
#include <gromox/proc_common.h>
#include <gromox/util.hpp>
#include "common_util.h"
#include "emsmdb_interface.h"
#include "ftstream_producer.h"
#include "logon_object.h"

using namespace std::string_literals;
using namespace gromox;

static void ftstream_producer_try_recode_nbp(FTSTREAM_PRODUCER *pstream) try
{
	auto last_seek = pstream->bp_list.size() == 0 ? 0 : pstream->bp_list.back().offset;
	if (pstream->offset - last_seek < FTSTREAM_PRODUCER_POINT_LENGTH)
		return;
	point_node p = {point_type::normal_break, pstream->offset};
	pstream->bp_list.push_back(std::move(p));
} catch (const std::bad_alloc &) {
	mlog(LV_WARN, "W-1601: ENOMEM");
}

static void ftstream_producer_record_nbp(FTSTREAM_PRODUCER *pstream,
    uint32_t nbp) try
{
	if (pstream->bp_list.size() > 0 && nbp <= pstream->bp_list.back().offset)
		return;
	point_node p = {point_type::normal_break, nbp};
	pstream->bp_list.emplace_back(std::move(p));
} catch (const std::bad_alloc &) {
	mlog(LV_WARN, "W-1602: ENOMEM");
}

static void ftstream_producer_record_lvp(FTSTREAM_PRODUCER *pstream,
     uint32_t position, uint32_t length) try
{
	auto pnode = pstream->bp_list.rbegin();
	if (pnode == pstream->bp_list.rend() || position > pnode->offset) {
		point_node p = {point_type::normal_break, position};
		pstream->bp_list.emplace_back(std::move(p));
		pnode = pstream->bp_list.rbegin();
	}
	if (position + length <= pnode->offset)
		return;
	point_node p = {point_type::long_var, position + length};
	pstream->bp_list.emplace_back(std::move(p));
} catch (const std::bad_alloc &) {
	mlog(LV_WARN, "W-1603: ENOMEM");
}

static void ftstream_producer_record_wsp(FTSTREAM_PRODUCER *pstream,
    uint32_t position, uint32_t length) try
{
	auto pnode = pstream->bp_list.rbegin();
	if (pnode == pstream->bp_list.rend() || position > pnode->offset) {
		point_node p = {point_type::normal_break, position};
		pstream->bp_list.emplace_back(std::move(p));
		pnode = pstream->bp_list.rbegin();
	}
	if (position + length <= pnode->offset)
		return;
	point_node p = {point_type::wstring, position + length};
	pstream->bp_list.emplace_back(std::move(p));
} catch (const std::bad_alloc &) {
	mlog(LV_WARN, "W-1604: ENOMEM");
}

static bool fxstream_producer_open(fxstream_producer &p)
{
	if (p.fd >= 0)
		return true; /* already open */
	auto path = LOCAL_DISK_TMPDIR;
	auto ret = p.fd.open_anon(path, O_RDWR | O_TRUNC);
	if (ret >= 0)
		return true;
	mlog(LV_ERR, "E-1338: open_anon(%s)[%s]: %s", path, p.fd.m_path.c_str(),
		strerror(-ret));
	return false;
}

static BOOL ftstream_producer_write_internal(
	FTSTREAM_PRODUCER *pstream,
	const void *pbuff, uint32_t size)
{	
	if (size >= FTSTREAM_PRODUCER_BUFFER_LENGTH
		|| FTSTREAM_PRODUCER_BUFFER_LENGTH -
		pstream->buffer_offset < size) {
		if (!fxstream_producer_open(*pstream))
			return false;
		auto ret = write(pstream->fd, pstream->buffer, pstream->buffer_offset);
		if (pstream->buffer_offset != 0 &&
		    (ret < 0 || static_cast<size_t>(ret) != pstream->buffer_offset))
			return FALSE;	
		pstream->buffer_offset = 0;
		pstream->read_offset = 0;
	}
	if (size >= FTSTREAM_PRODUCER_BUFFER_LENGTH) {
		auto ret = write(pstream->fd, pbuff, size);
		if (ret < 0 || static_cast<size_t>(ret) != size)
			return FALSE;
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
	if (!ftstream_producer_write_internal(pstream, &v, sizeof(float)))
		return FALSE;	
	ftstream_producer_try_recode_nbp(pstream);
	return TRUE;
}

static BOOL ftstream_producer_write_double(
	FTSTREAM_PRODUCER *pstream, double v)
{
	if (!ftstream_producer_write_internal(pstream, &v, sizeof(double)))
		return FALSE;	
	ftstream_producer_try_recode_nbp(pstream);
	return TRUE;
}

static BOOL ftstream_producer_write_wstring(
	FTSTREAM_PRODUCER *pstream, const char *pstr)
{
	uint32_t position;
	auto len = utf8_to_utf16_len(pstr);
	auto pbuff = gromox::me_alloc<char>(len);
	if (pbuff == nullptr)
		return FALSE;
	auto utf16_len = utf8_to_utf16le(pstr, pbuff, len);
	if (utf16_len < 2) {
		pbuff[0] = '\0';
		pbuff[1] = '\0';
		len = 2;
	} else {
		len = utf16_len;
	}
	if (!pstream->write_uint32(len)) {
		free(pbuff);
		return FALSE;
	}
	position = pstream->offset;
	if (!ftstream_producer_write_internal(pstream, pbuff, len)) {
		free(pbuff);
		return FALSE;
	}
	free(pbuff);
	if (len >= FTSTREAM_PRODUCER_POINT_LENGTH)
		ftstream_producer_record_wsp(pstream, position, len);
	else
		ftstream_producer_try_recode_nbp(pstream);
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
	if (!ftstream_producer_write_internal(pstream, pstr, len))
		return FALSE;
	if (len >= FTSTREAM_PRODUCER_POINT_LENGTH)
		ftstream_producer_record_lvp(pstream, position, len);
	else
		ftstream_producer_try_recode_nbp(pstream);
	return TRUE;
}

static BOOL ftstream_producer_write_guid(
	FTSTREAM_PRODUCER *pstream, const GUID *pguid)
{
	BINARY *pbin;
	
	pbin = common_util_guid_to_binary(*pguid);
	if (pbin == nullptr)
		return FALSE;
	if (!ftstream_producer_write_internal(pstream, pbin->pb, 16))
		return FALSE;
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
	if (pbin->cb != 0 &&
	    !ftstream_producer_write_internal(pstream, pbin->pb, pbin->cb))
		return FALSE;
	if (pbin->cb >= FTSTREAM_PRODUCER_POINT_LENGTH)
		ftstream_producer_record_lvp(pstream, position, pbin->cb);
	else
		ftstream_producer_try_recode_nbp(pstream);
	return TRUE;
}

static int ftstream_producer_write_propdef(FTSTREAM_PRODUCER *pstream,
	uint16_t proptype, uint16_t propid)
{
	uint16_t tmp_val;
	EXT_PUSH ext_push;
	char tmp_buff[1024];
	PROPERTY_NAME propname;

	if (propid == PROP_ID_INVALID)
		mlog(LV_WARN, "W-1271: ftstream with PROP_ID_INVALID seen");
	if (is_nameprop_id(propid)) {
		if (!pstream->plogon->get_named_propname(propid, &propname))
			return -1;
		if (propname.kind == KIND_NONE) {
			mlog(LV_WARN, "W-1566: propid %xh has no matching namedprop", propid);
			return 2;
		}
	}
	
	tmp_val = cpu_to_le16(proptype);
	if (!ftstream_producer_write_internal(pstream, &tmp_val, sizeof(uint16_t)))
		return -1;
	tmp_val = cpu_to_le16(propid);
	if (!ftstream_producer_write_internal(pstream, &tmp_val, sizeof(uint16_t)))
		return -1;
	if (!is_nameprop_id(propid)) {
		ftstream_producer_try_recode_nbp(pstream);
		return 0;
	}
	if (!ext_push.init(tmp_buff, sizeof(tmp_buff), EXT_FLAG_UTF16) ||
	    ext_push.p_guid(propname.guid) != EXT_ERR_SUCCESS ||
	    ext_push.p_uint8(propname.kind) != EXT_ERR_SUCCESS)
		return -1;
	switch (propname.kind) {
	case MNID_ID:
		if (ext_push.p_uint32(propname.lid) != EXT_ERR_SUCCESS)
			return -1;
		break;
	case MNID_STRING:
		if (ext_push.p_wstr(propname.pname) != EXT_ERR_SUCCESS)
			return -1;
		break;
	default:
		return -1;
	}
	if (!ftstream_producer_write_internal(pstream, tmp_buff, ext_push.m_offset))
		return -1;
	ftstream_producer_try_recode_nbp(pstream);
	return 0;
}

static BOOL ftstream_producer_write_propvalue(
	FTSTREAM_PRODUCER *pstream, TAGGED_PROPVAL *ppropval)
{
	uint16_t propid;
	uint16_t proptype;
	uint16_t write_type;
	
	propid = PROP_ID(ppropval->proptag);
	proptype = PROP_TYPE(ppropval->proptag);
	/* ignore PT_SVREID */
	if (proptype == PT_SVREID)
		return TRUE;
	if (ppropval->proptag == PR_MESSAGE_CLASS)
		proptype = PT_STRING8;
	write_type = proptype;
	if (propid == PROP_ID(MetaTagIdsetGiven)) {
		/* OXCFXICS v24 §3.2.5.2.1 */
		write_type = PT_LONG;
	} else if (proptype == PT_STRING8 || proptype == PT_UNICODE) {
		if (pstream->string_option & STRING_OPTION_FORCE_UNICODE) {
			if (proptype == PT_STRING8) {
				proptype = PT_UNICODE;
				write_type = PT_UNICODE;
				auto len = mb_to_utf8_len(static_cast<char *>(ppropval->pvalue));
				auto pvalue = cu_alloc<char>(len);
				if (pvalue == nullptr)
					return FALSE;
				if (common_util_convert_string(true,
				    static_cast<char *>(ppropval->pvalue), pvalue, len) <= 0)
					*pvalue = '\0';	
				ppropval->pvalue = pvalue;
			}
		} else if (pstream->string_option & STRING_OPTION_CPID) {
			if (proptype == PT_STRING8) {
				auto pinfo = emsmdb_interface_get_emsmdb_info();
				if (pinfo == nullptr)
					return FALSE;
				write_type = FXICS_CODEPAGE_FLAG | (uint16_t)pinfo->cpid;
			} else {
				write_type = FXICS_CODEPAGE_FLAG | 1200;
			}
		} else if (STRING_OPTION_NONE == pstream->string_option) {
			if (proptype == PT_UNICODE) {
				proptype = PT_STRING8;
				write_type = PT_STRING8;
				auto len = utf8_to_mb_len(static_cast<char *>(ppropval->pvalue));
				auto pvalue = cu_alloc<char>(len);
				if (pvalue == nullptr)
					return FALSE;
				if (common_util_convert_string(false,
				    static_cast<char *>(ppropval->pvalue), pvalue, len) <= 0)
					*pvalue = '\0';	
				ppropval->pvalue = pvalue;
			}
		}
	}
	auto ret = ftstream_producer_write_propdef(pstream, write_type, propid);
	if (ret < 0)
		return FALSE;
	if (ret == 2)
		return TRUE;
	
	switch (proptype) {
	case PT_SHORT:
		return ftstream_producer_write_uint16(pstream,
		       *static_cast<uint16_t *>(ppropval->pvalue));
	case PT_ERROR:
	case PT_LONG:
		return pstream->write_uint32(*static_cast<uint32_t *>(ppropval->pvalue));
	case PT_FLOAT:
		return ftstream_producer_write_float(pstream,
		       *static_cast<float *>(ppropval->pvalue));
	case PT_DOUBLE:
	case PT_APPTIME:
		return ftstream_producer_write_double(pstream,
		       *static_cast<double *>(ppropval->pvalue));
	case PT_BOOLEAN:
		return ftstream_producer_write_uint16(pstream,
		       *static_cast<uint8_t *>(ppropval->pvalue));
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME:
		return ftstream_producer_write_uint64(pstream,
		       *static_cast<uint64_t *>(ppropval->pvalue));
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
	case PT_MV_SHORT: {
		auto ar = static_cast<const SHORT_ARRAY *>(ppropval->pvalue);
		if (!pstream->write_uint32(ar->count))
			return FALSE;
		for (uint32_t i = 0; i < ar->count; ++i)
			if (!ftstream_producer_write_uint16(pstream, ar->ps[i]))
				return FALSE;
		return TRUE;
	}
	case PT_MV_LONG: {
		auto ar = static_cast<const LONG_ARRAY *>(ppropval->pvalue);
		if (!pstream->write_uint32(ar->count))
			return FALSE;
		for (uint32_t i = 0; i < ar->count; ++i)
			if (!pstream->write_uint32(ar->pl[i]))
				return FALSE;
		return TRUE;
	}
	case PT_MV_CURRENCY:
	case PT_MV_I8:
	case PT_MV_SYSTIME: {
		auto ar = static_cast<const LONGLONG_ARRAY *>(ppropval->pvalue);
		if (!pstream->write_uint32(ar->count))
			return FALSE;
		for (uint32_t i = 0; i < ar->count; ++i)
			if (!ftstream_producer_write_uint64(pstream, ar->pll[i]))
				return FALSE;
		return TRUE;
	}
	case PT_MV_FLOAT: {
		auto fa = static_cast<FLOAT_ARRAY *>(ppropval->pvalue);
		if (!pstream->write_uint32(fa->count))
			return false;
		for (size_t i = 0; i < fa->count; ++i)
			if (!ftstream_producer_write_float(pstream, fa->mval[i]))
				return false;
		return TRUE;
	}
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME: {
		auto fa = static_cast<DOUBLE_ARRAY *>(ppropval->pvalue);
		if (!pstream->write_uint32(fa->count))
			return false;
		for (size_t i = 0; i < fa->count; ++i)
			if (!ftstream_producer_write_double(pstream, fa->mval[i]))
				return false;
		return TRUE;
	}
	case PT_MV_STRING8: {
		auto ar = static_cast<const STRING_ARRAY *>(ppropval->pvalue);
		if (!pstream->write_uint32(ar->count))
			return FALSE;
		for (uint32_t i = 0; i < ar->count; ++i)
			if (!ftstream_producer_write_string(pstream, ar->ppstr[i]))
				return FALSE;
		return TRUE;
	}
	case PT_MV_UNICODE: {
		auto ar = static_cast<const STRING_ARRAY *>(ppropval->pvalue);
		if (!pstream->write_uint32(ar->count))
			return FALSE;
		for (uint32_t i = 0; i < ar->count; ++i)
			if (!ftstream_producer_write_wstring(pstream, ar->ppstr[i]))
				return FALSE;
		return TRUE;
	}
	case PT_MV_CLSID: {
		auto ar = static_cast<const GUID_ARRAY *>(ppropval->pvalue);
		if (!pstream->write_uint32(ar->count))
			return FALSE;
		for (uint32_t i = 0; i < ar->count; ++i)
			if (!ftstream_producer_write_guid(pstream, &ar->pguid[i]))
				return FALSE;
		return TRUE;
	}
	case PT_MV_BINARY: {
		auto ar = static_cast<const BINARY_ARRAY *>(ppropval->pvalue);
		if (!pstream->write_uint32(ar->count))
			return FALSE;
		for (uint32_t i = 0; i < ar->count; ++i)
			if (!ftstream_producer_write_binary(pstream, &ar->pbin[i]))
				return FALSE;
		return TRUE;
	}
	}
	return FALSE;
}

BOOL ftstream_producer::write_proplist(const TPROPVAL_ARRAY *pproplist)
{
	auto pstream = this;
	for (size_t i = 0; i < pproplist->count; ++i)
		if (!ftstream_producer_write_propvalue(pstream, &pproplist->ppropval[i]))
			return FALSE;	
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
	if (pattachment->pembedded != nullptr &&
	    !ftstream_producer_write_embeddedmessage(pstream,
	    b_delprop, pattachment->pembedded))
		return FALSE;
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
	if (b_delprop) {
		if (!pstream->write_uint32(MetaTagFXDelProp))
			return FALSE;
		if (!pstream->write_uint32(PR_MESSAGE_RECIPIENTS))
			return FALSE;
	}
	if (pchildren->prcpts != nullptr)
		for (size_t i = 0; i < pchildren->prcpts->count; ++i)
			if (!ftstream_producer_write_recipient(pstream,
			    pchildren->prcpts->pparray[i]))
				return FALSE;
	if (b_delprop) {
		if (!pstream->write_uint32(MetaTagFXDelProp))
			return FALSE;
		if (!pstream->write_uint32(PR_MESSAGE_ATTACHMENTS))
			return FALSE;
	}
	if (pchildren->pattachments == nullptr)
		return TRUE;
	for (size_t i = 0; i < pchildren->pattachments->count; ++i) {
		if (!ftstream_producer_write_attachment(pstream,
		    b_delprop, pchildren->pattachments->pplist[i]))
			return FALSE;
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
	auto pbool = pmessage->proplist.get<uint8_t>(PR_ASSOCIATED);
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
	if (!ftstream_producer_write_messagechangeheader(pstream, pchgheader))
		return FALSE;	
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
			if (ext_push.p_guid(propname.guid) != EXT_ERR_SUCCESS ||
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
	
	if (!ftstream_producer_write_groupinfo(pstream, pmsg->pgpinfo))
		return FALSE;
	if (!write_uint32(MetaTagIncrSyncGroupId))
		return FALSE;
	if (!write_uint32(pmsg->group_id))
		return FALSE;	
	if (!write_uint32(INCRSYNCCHGPARTIAL))
		return FALSE;
	if (!ftstream_producer_write_messagechangeheader(pstream, pchgheader))
		return FALSE;	
	for (size_t i = 0; i < pmsg->count; ++i) {
		if (!write_uint32(MetaTagIncrementalSyncMessagePartial))
			return FALSE;
		if (!write_uint32(pmsg->pchanges[i].index))
			return FALSE;	
		for (size_t j = 0; j < pmsg->pchanges[i].proplist.count; ++j) {
			switch(pmsg->pchanges[i].proplist.ppropval[j].proptag) {
			case PR_MESSAGE_RECIPIENTS:
				if (pmsg->children.prcpts == nullptr)
					break;
				if (!write_uint32(MetaTagFXDelProp))
					return FALSE;
				if (!write_uint32(PR_MESSAGE_RECIPIENTS))
					return FALSE;
				for (size_t k = 0; k < pmsg->children.prcpts->count; ++k)
					if (!ftstream_producer_write_recipient(pstream,
					    pmsg->children.prcpts->pparray[k]))
						return FALSE;
				break;
			case PR_MESSAGE_ATTACHMENTS:
				if (pmsg->children.pattachments == nullptr)
					break;
				if (!write_uint32(MetaTagFXDelProp))
					return FALSE;
				if (!write_uint32(PR_MESSAGE_ATTACHMENTS))
					return FALSE;
				for (size_t k = 0; k < pmsg->children.pattachments->count; ++k)
					if (!ftstream_producer_write_attachment(pstream,
					    TRUE, pmsg->children.pattachments->pplist[k]))
						return FALSE;
				break;
			default:
				if (!ftstream_producer_write_propvalue(pstream,
				    &pmsg->pchanges[i].proplist.ppropval[j]))
					return FALSE;	
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
	if (!ftstream_producer_write_uint16(pstream, b_fai))
		return FALSE;
	return TRUE;
}

BOOL ftstream_producer::write_progresstotal(const PROGRESS_INFORMATION *pprogtotal)
{
	/*
	 * We are sending 64-bit values. It's Outlook's fault for not
	 * displaying them.
	 * https://docs.microsoft.com/en-us/outlook/troubleshoot/synchronization/status-bar-never-shows-more-than-3-99-gb
	 */
	auto pstream = this;
	if (!write_uint32(INCRSYNCPROGRESSMODE))
		return FALSE;
	if (!write_uint32(PT_BINARY))
		return FALSE;
	/* binary length */
	if (!write_uint32(32))
		return FALSE;
	if (!ftstream_producer_write_uint16(pstream, pprogtotal->version))
		return FALSE;
	if (!ftstream_producer_write_uint16(pstream, pprogtotal->padding1))
		return FALSE;
	if (!write_uint32(pprogtotal->fai_count))
		return FALSE;
	if (!ftstream_producer_write_uint64(pstream, pprogtotal->fai_size))
		return FALSE;
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
	for (size_t i = 0; i < pfldchgs->count; ++i)
		if (!ftstream_producer_write_folderchange(pstream,
		    &pfldchgs->pfldchgs[i]))
			return FALSE;
	if (pdels != nullptr && !write_deletions(pdels))
		return FALSE;
	if (!write_state(pstate))
		return FALSE;
	if (!write_uint32(INCRSYNCEND))
		return FALSE;
	return TRUE;
}

std::unique_ptr<ftstream_producer>
ftstream_producer::create(logon_object *plogon, uint8_t string_option) try
{
	auto path = LOCAL_DISK_TMPDIR;
	if (mkdir(path, 0777) < 0 && errno != EEXIST) {
		mlog(LV_ERR, "E-1422: mkdir %s: %s", path, strerror(errno));
		return nullptr;
	}
	std::unique_ptr<ftstream_producer> pstream(new ftstream_producer);
	pstream->plogon = plogon;
	pstream->string_option = string_option;
	return pstream;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1452: ENOMEM");
	return nullptr;
}

BOOL ftstream_producer::read_buffer(void *pbuff, uint16_t *plen, BOOL *pb_last)
{
	auto pstream = this;
	uint32_t cur_offset;
	
	if (!pstream->b_read) {
		auto pnode = pstream->bp_list.rbegin();
		if (pnode == pstream->bp_list.rend() ||
		    pnode->offset != pstream->offset)
			ftstream_producer_record_nbp(pstream, pstream->offset);
		pstream->b_read = TRUE;
		if (-1 != pstream->fd) {
			auto ret = write(pstream->fd, pstream->buffer, pstream->buffer_offset);
			if (pstream->buffer_offset != 0 &&
			    (ret < 0 || static_cast<size_t>(ret) != pstream->buffer_offset))
				return FALSE;
			lseek(pstream->fd, 0, SEEK_SET);
		}
		cur_offset = 0;
	} else {
		cur_offset = pstream->fd != -1 ? lseek(pstream->fd, 0, SEEK_CUR) : pstream->read_offset;
	}
	for (auto pnode = pstream->bp_list.begin();
	     pnode != pstream->bp_list.end(); ++pnode) {
		auto ppoint = &*pnode;
		if (ppoint->offset - cur_offset <= *plen)
			continue;
		if (ppoint->type == point_type::normal_break) {
			if (pnode == pstream->bp_list.begin())
				return FALSE;
			auto p2 = std::prev(pnode);
			if (p2->offset < cur_offset)
				return FALSE;
			*plen = p2->offset - cur_offset;
		} else if (ppoint->type == point_type::wstring) {
			/* align to 2 bytes */
			if (pnode == pstream->bp_list.begin()) {
				if ((*plen) % 2 != 0)
					(*plen) --;
			} else {
				auto p2 = std::prev(pnode);
				if ((*plen - (p2->offset - cur_offset)) % 2 != 0)
					(*plen) --;
			}
		}
		pstream->bp_list.erase(pstream->bp_list.begin(), pnode);
		if (-1 != pstream->fd) {
			if (read(pstream->fd, pbuff, *plen) != *plen)
				return FALSE;
		} else {
			memcpy(pbuff, pstream->buffer + pstream->read_offset, *plen);
			pstream->read_offset += *plen;
		}
		*pb_last = FALSE;
		return TRUE;
	}
	if (pstream->bp_list.size() == 0)
		return FALSE;
	auto ppoint = &pstream->bp_list.back();
	if (ppoint->offset < cur_offset)
		return FALSE;
	*plen = ppoint->offset - cur_offset;
	pstream->bp_list.clear();
	if (-1 != pstream->fd) {
		if (read(pstream->fd, pbuff, *plen) != *plen)
			return FALSE;
	} else {
		memcpy(pbuff, pstream->buffer + pstream->read_offset, *plen);
		pstream->read_offset += *plen;
	}
	*pb_last = TRUE;
	pstream->fd.close();
	pstream->offset = 0;
	pstream->buffer_offset = 0;
	pstream->read_offset = 0;
	pstream->b_read = FALSE;
	return TRUE;
}
