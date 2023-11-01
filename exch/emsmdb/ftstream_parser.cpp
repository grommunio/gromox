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
#include <utility>
#include <sys/stat.h>
#include <sys/types.h>
#include <libHX/io.h>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/paths.h>
#include <gromox/proc_common.h>
#include <gromox/util.hpp>
#include "common_util.h"
#include "fastupctx_object.h"
#include "ftstream_parser.h"
#include "rop_processor.h"

using namespace std::string_literals;
using namespace gromox;

enum {
	FTSTREAM_PARSER_READ_FAIL = -1,
	FTSTREAM_PARSER_READ_OK,
	FTSTREAM_PARSER_READ_CONTINUE
};


static BOOL ftstream_parser_read_uint16(
	FTSTREAM_PARSER *pstream, uint16_t *pv)
{
	if (read(pstream->fd, pv, sizeof(*pv)) != sizeof(*pv))
		return FALSE;
	*pv = le16_to_cpu(*pv);
	pstream->offset += sizeof(uint16_t);
	return TRUE;
}

static BOOL ftstream_parser_read_uint32(
	FTSTREAM_PARSER *pstream, uint32_t *pv)
{
	if (read(pstream->fd, pv, sizeof(*pv)) != sizeof(*pv))
		return FALSE;
	*pv = le32_to_cpu(*pv);
	pstream->offset += sizeof(uint32_t);
	return TRUE;
}

static BOOL ftstream_parser_read_uint64(
	FTSTREAM_PARSER *pstream, uint64_t *pv)
{
	if (read(pstream->fd, pv, sizeof(*pv)) != sizeof(*pv))
		return FALSE;
	*pv = le64_to_cpu(*pv);
	pstream->offset += sizeof(uint64_t);
	return TRUE;
}

static BOOL ftstream_parser_read_float(FTSTREAM_PARSER *pstream, float *pv)
{
	if (read(pstream->fd, pv, sizeof(*pv)) != sizeof(*pv))
		return FALSE;
	pstream->offset += sizeof(float);
	static_assert(sizeof(float) == sizeof(uint32_t));
	return TRUE;
}

static BOOL ftstream_parser_read_double(FTSTREAM_PARSER *pstream, double *pv)
{
	if (read(pstream->fd, pv, sizeof(*pv)) != sizeof(*pv))
		return FALSE;
	pstream->offset += sizeof(double);
	return TRUE;
}

static char* ftstream_parser_read_wstring(
	FTSTREAM_PARSER *pstream, BOOL *pb_continue)
{
	uint32_t len;
	uint32_t tmp_len;
	uint32_t origin_offset;
	
	*pb_continue = FALSE;
	origin_offset = pstream->offset;
	if (!ftstream_parser_read_uint32(pstream, &len))
		return NULL;
	if (len >= g_max_mail_len)
		return NULL;	
	if (origin_offset + sizeof(uint32_t) + len >
		pstream->st_size) {
		*pb_continue = TRUE;
		return NULL;
	}
	tmp_len = 2*len;
	auto pbuff = gromox::me_alloc<char>(len + 2);
	if (pbuff == nullptr)
		return NULL;
	auto ret = read(pstream->fd, pbuff, len);
	if (ret < 0 || static_cast<size_t>(ret) != len) {
		free(pbuff);
		return NULL;
	}
	pstream->offset += len;
	/* if trail nulls not found, append them */
	if (0 != pbuff[len - 2] && 0 != pbuff[len - 1]) {
		pbuff[len] = 0;
		pbuff[len + 1] = 0;
		len += 2;
	}
	auto pbuff1 = cu_alloc<char>(tmp_len);
	if (NULL == pbuff1) {
		free(pbuff);
		return NULL;
	}
	if (!utf16le_to_utf8(pbuff, len, pbuff1, tmp_len)) {
		free(pbuff);
		return NULL;
	}
	free(pbuff);
	return pbuff1;
}

static char* ftstream_parser_read_string(
	FTSTREAM_PARSER *pstream, BOOL *pb_continue)
{
	uint32_t len;
	uint32_t origin_offset;
	
	*pb_continue = FALSE;
	origin_offset = pstream->offset;
	if (!ftstream_parser_read_uint32(pstream, &len))
		return NULL;
	if (len >= g_max_mail_len)
		return nullptr;
	if (origin_offset + sizeof(uint32_t) + len >
		pstream->st_size) {
		*pb_continue = TRUE;
		return NULL;
	}
	auto pbuff = cu_alloc<char>(len + 1);
	if (pbuff == nullptr)
		return NULL;
	auto ret = read(pstream->fd, pbuff, len);
	if (ret < 0 || static_cast<size_t>(ret) != len)
		return NULL;
	pstream->offset += len;
	/* if trail null not found, append it */
	if (pbuff[len-1] != '\0')
		pbuff[len] = '\0';
	return pbuff;
}

static char* ftstream_parser_read_naked_wstring(
	FTSTREAM_PARSER *pstream)
{
	uint32_t len;
	char buff[1024];
	uint32_t offset;
	
	offset = 0;
	while (true) {
		if (read(pstream->fd, &buff[offset], 2) != 2)
			return NULL;
		if (buff[offset] == '\0' && buff[offset+1] == '\0')
			break;
		offset += 2;
		if (offset == sizeof(buff))
			return NULL;
	}
	len = offset + 2;
	pstream->offset += len;
	auto pbuff = cu_alloc<char>(2 * len);
	if (pbuff == nullptr)
		return NULL;
	if (!utf16le_to_utf8(buff, len, pbuff, 2 * len))
		return NULL;
	return pbuff;
}

static BOOL ftstream_parser_read_guid(
	FTSTREAM_PARSER *pstream, GUID *pguid)
{
	if (!ftstream_parser_read_uint32(pstream, &pguid->time_low))
		return FALSE;
	if (!ftstream_parser_read_uint16(pstream, &pguid->time_mid))
		return FALSE;
	if (!ftstream_parser_read_uint16(pstream, &pguid->time_hi_and_version))
		return FALSE;
	if (read(pstream->fd, pguid->clock_seq, 2) != 2)
		return FALSE;
	pstream->offset += 2;
	if (read(pstream->fd, pguid->node, 6) != 6)
		return FALSE;
	pstream->offset += 6;
	return TRUE;
}

static BOOL ftstream_parser_read_svreid(
	FTSTREAM_PARSER *pstream,
	SVREID *psvreid, BOOL *pb_continue)
{
	uint32_t len;
	uint8_t ours;
	uint32_t origin_offset;
	
	*pb_continue = FALSE;
	origin_offset = pstream->offset;
	if (!ftstream_parser_read_uint32(pstream, &len))
		return FALSE;
	if (origin_offset + sizeof(uint32_t) + len >
		pstream->st_size) {
		*pb_continue = TRUE;
		return FALSE;
	}
	if (len == 0)
		abort(); /* if this ever happens, make cb=0,pb=NULL */
	if (read(pstream->fd, &ours, sizeof(uint8_t)) != sizeof(uint8_t))
		return FALSE;
	pstream->offset += sizeof(uint8_t);
	if (0 == ours) {
		psvreid->pbin = cu_alloc<BINARY>();
		if (psvreid->pbin == nullptr)
			return FALSE;
		psvreid->pbin->cb = len - 1;
		if (0 == psvreid->pbin->cb) {
			psvreid->pbin->pb = NULL;
		} else {
			psvreid->pbin->pv = common_util_alloc(psvreid->pbin->cb);
			if (psvreid->pbin->pv == nullptr)
				return FALSE;
			auto ret = read(pstream->fd, psvreid->pbin->pv, psvreid->pbin->cb);
			if (ret < 0 || static_cast<size_t>(ret) != psvreid->pbin->cb)
				return FALSE;
			pstream->offset += psvreid->pbin->cb;
		}
	}
	if (len != 21)
		return FALSE;
	psvreid->pbin = NULL;
	if (!ftstream_parser_read_uint64(pstream, &psvreid->folder_id))
		return FALSE;
	if (!ftstream_parser_read_uint64(pstream, &psvreid->message_id))
		return FALSE;
	if (!ftstream_parser_read_uint32(pstream, &psvreid->instance))
		return FALSE;
	return TRUE;
}

static BOOL ftstream_parser_read_binary(
	FTSTREAM_PARSER *pstream, BINARY *pbin,
	BOOL *pb_continue)
{
	uint32_t origin_offset;
	
	*pb_continue = FALSE;
	origin_offset = pstream->offset;
	if (!ftstream_parser_read_uint32(pstream, &pbin->cb))
		return FALSE;
	if (pbin->cb >= g_max_mail_len)
		return FALSE;	
	if (origin_offset + sizeof(uint32_t) +
		pbin->cb > pstream->st_size) {
		*pb_continue = TRUE;
		return FALSE;
	}
	if (0 == pbin->cb) {
		pbin->pb = NULL;
		return TRUE;
	}
	pbin->pv = common_util_alloc(pbin->cb);
	if (pbin->pv == nullptr)
		return FALSE;
	auto ret = read(pstream->fd, pbin->pv, pbin->cb);
	if (ret < 0 || static_cast<size_t>(ret) != pbin->cb)
		return FALSE;
	pstream->offset += pbin->cb;
	return TRUE;
}

static PROPERTY_NAME* ftstream_parser_read_property_name(
	FTSTREAM_PARSER *pstream)
{
	auto pname = cu_alloc<PROPERTY_NAME>();
	if (pname == nullptr)
		return NULL;
	if (!ftstream_parser_read_guid(pstream, &pname->guid))
		return NULL;	
	if (read(pstream->fd, &pname->kind, sizeof(uint8_t)) != sizeof(uint8_t))
		return NULL;
	pstream->offset += sizeof(uint8_t);
	pname->lid = 0;
	pname->pname = NULL;
	switch (pname->kind) {
	case MNID_ID:
		if (!ftstream_parser_read_uint32(pstream, &pname->lid))
			return nullptr;
		return pname;
	case MNID_STRING:
		pname->pname = ftstream_parser_read_naked_wstring(pstream);
		if (pname->pname == nullptr)
			return NULL;
		return pname;
	}
	return NULL;
}

static int ftstream_parser_read_element(FTSTREAM_PARSER &stream,
    uint32_t &marker, TAGGED_PROPVAL &propval)
{
	auto pstream = &stream;
	uint32_t count;
	BOOL b_continue;
	uint32_t atom_element = 0;
	PROPERTY_NAME *ppropname;
	
	uint32_t origin_offset = pstream->offset;
	if (origin_offset == pstream->st_size)
		return FTSTREAM_PARSER_READ_CONTINUE;
	if (!ftstream_parser_read_uint32(pstream, &atom_element))
		return FTSTREAM_PARSER_READ_FAIL;
	switch (atom_element) {
	case STARTTOPFLD:
	case STARTSUBFLD:
	case ENDFOLDER:
	case STARTMESSAGE:
	case ENDMESSAGE:
	case STARTFAIMSG:
	case STARTEMBED:
	case ENDEMBED:
	case STARTRECIP:
	case ENDTORECIP:
	case NEWATTACH:
	case ENDATTACH:
	case INCRSYNCCHG:
	case INCRSYNCCHGPARTIAL:
	case INCRSYNCDEL:
	case INCRSYNCEND:
	case INCRSYNCREAD:
	case INCRSYNCSTATEBEGIN:
	case INCRSYNCSTATEEND:
	case INCRSYNCPROGRESSMODE:
	case INCRSYNCPROGRESSPERMSG:
	case INCRSYNCMESSAGE:
	case INCRSYNCGROUPINFO:
	case FXERRORINFO:
		marker = atom_element;
		return FTSTREAM_PARSER_READ_OK;
	}
	marker = 0;
	uint16_t proptype = PROP_TYPE(atom_element);
	uint16_t propid = PROP_ID(atom_element);
	/* OXCFXICS v24 3.2.5.2.1 */
	if (atom_element == MetaTagIdsetGiven)
		proptype = PT_BINARY;
	if (propid == PROP_ID_INVALID)
		mlog(LV_WARN, "W-1272: ftstream with PROP_ID_INVALID seen");
	if (is_nameprop_id(propid)) {
		ppropname = ftstream_parser_read_property_name(pstream);
		if (ppropname == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		if (!pstream->plogon->get_named_propid(TRUE, ppropname, &propid))
			return FTSTREAM_PARSER_READ_FAIL;
	}
	if (pstream->st_size == pstream->offset)
		goto CONTINUE_WAITING;
	propval.proptag = PROP_TAG(proptype, propid);
	if (proptype & FXICS_CODEPAGE_FLAG) {
		/* codepage string */
		auto codepage = proptype & ~FXICS_CODEPAGE_FLAG;
		if (1200 == codepage) {
			propval.proptag = CHANGE_PROP_TYPE(propval.proptag, PT_UNICODE);
			propval.pvalue = ftstream_parser_read_wstring(pstream, &b_continue);
		} else {
			propval.pvalue = ftstream_parser_read_string(pstream, &b_continue);
		}
		if (propval.pvalue == nullptr) {
			if (b_continue)
				goto CONTINUE_WAITING;
			return FTSTREAM_PARSER_READ_FAIL;
		}
		return FTSTREAM_PARSER_READ_OK;
	}
	switch (proptype) {
	case PT_SHORT: {
		auto v = cu_alloc<uint16_t>();
		if (v == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		propval.pvalue = v;
		return ftstream_parser_read_uint16(pstream, v) ? FTSTREAM_PARSER_READ_OK : FTSTREAM_PARSER_READ_FAIL;
	}
	case PT_ERROR:
	case PT_LONG: {
		auto v = cu_alloc<uint32_t>();
		if (v == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		propval.pvalue = v;
		return ftstream_parser_read_uint32(pstream, v) ? FTSTREAM_PARSER_READ_OK : FTSTREAM_PARSER_READ_FAIL;
	}
	case PT_FLOAT: {
		auto v = cu_alloc<float>();
		if (v == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		propval.pvalue = v;
		if (read(pstream->fd, v, sizeof(*v)) != sizeof(*v))
			return FTSTREAM_PARSER_READ_FAIL;	
		pstream->offset += sizeof(*v);
		return FTSTREAM_PARSER_READ_OK;
	}
	case PT_DOUBLE:
	case PT_APPTIME: {
		auto v = cu_alloc<double>();
		if (v == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		propval.pvalue = v;
		if (read(pstream->fd, v, sizeof(*v)) != sizeof(*v))
			return FTSTREAM_PARSER_READ_FAIL;	
		pstream->offset += sizeof(*v);
		return FTSTREAM_PARSER_READ_OK;
	}
	case PT_BOOLEAN: {
		auto v = cu_alloc<uint8_t>();
		if (v == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		propval.pvalue = v;
		uint16_t fake_byte = 0;
		if (!ftstream_parser_read_uint16(pstream, &fake_byte))
			return FTSTREAM_PARSER_READ_FAIL;	
		*v = fake_byte;
		return FTSTREAM_PARSER_READ_OK;
	}
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME: {
		auto v = cu_alloc<uint64_t>();
		if (v == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		propval.pvalue = v;
		return ftstream_parser_read_uint64(pstream, v) ? FTSTREAM_PARSER_READ_OK : FTSTREAM_PARSER_READ_FAIL;
	}
	case PT_STRING8:
		propval.pvalue = ftstream_parser_read_string(pstream, &b_continue);
		if (propval.pvalue != nullptr)
			return FTSTREAM_PARSER_READ_OK;
		if (b_continue)
			goto CONTINUE_WAITING;
		return FTSTREAM_PARSER_READ_FAIL;
	case PT_UNICODE:
		propval.pvalue = ftstream_parser_read_wstring(pstream, &b_continue);
		if (propval.pvalue != nullptr)
			return FTSTREAM_PARSER_READ_OK;
		if (b_continue)
			goto CONTINUE_WAITING;
		return FTSTREAM_PARSER_READ_FAIL;
	case PT_CLSID: {
		auto v = cu_alloc<GUID>();
		if (v == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		propval.pvalue = v;
		return ftstream_parser_read_guid(pstream, v) ? FTSTREAM_PARSER_READ_OK : FTSTREAM_PARSER_READ_FAIL;
	}
	case PT_SVREID: {
		auto v = cu_alloc<SVREID>();
		if (v == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		propval.pvalue = v;
		if (ftstream_parser_read_svreid(pstream, v, &b_continue))
			return FTSTREAM_PARSER_READ_OK;
		if (b_continue)
			goto CONTINUE_WAITING;
		return FTSTREAM_PARSER_READ_FAIL;
	}
	case PT_OBJECT:
	case PT_BINARY: {
		auto v = cu_alloc<BINARY>();
		if (v == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		propval.pvalue = v;
		if (ftstream_parser_read_binary(pstream, v, &b_continue))
			return FTSTREAM_PARSER_READ_OK;
		if (b_continue)
			goto CONTINUE_WAITING;
		return FTSTREAM_PARSER_READ_FAIL;
	}
	case PT_MV_SHORT: {
		auto sa = cu_alloc<SHORT_ARRAY>();
		propval.pvalue = sa;
		if (sa == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		if (!ftstream_parser_read_uint32(pstream, &count))
			return FTSTREAM_PARSER_READ_FAIL;
		if (count * sizeof(uint16_t) > 0x10000)
			return FTSTREAM_PARSER_READ_FAIL;
		if (pstream->st_size < count * sizeof(uint16_t) + pstream->offset)
			goto CONTINUE_WAITING;
		sa->count = count;
		if (0 == count) {
			sa->ps = nullptr;
		} else {
			sa->ps = cu_alloc<uint16_t>(count);
			if (sa->ps == nullptr)
				return FTSTREAM_PARSER_READ_FAIL;
		}
		for (size_t i = 0; i < count; ++i)
			if (!ftstream_parser_read_uint16(pstream, &sa->ps[i]))
				return FTSTREAM_PARSER_READ_FAIL;	
		return FTSTREAM_PARSER_READ_OK;
	}
	case PT_MV_LONG: {
		auto la = cu_alloc<LONG_ARRAY>();
		propval.pvalue = la;
		if (la == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		if (!ftstream_parser_read_uint32(pstream, &count))
			return FTSTREAM_PARSER_READ_FAIL;
		if (count * sizeof(uint32_t) > 0x10000)
			return FTSTREAM_PARSER_READ_FAIL;
		if (pstream->st_size < count * sizeof(uint32_t) + pstream->offset)
			goto CONTINUE_WAITING;
		la->count = count;
		if (0 == count) {
			la->pl = nullptr;
		} else {
			la->pl = cu_alloc<uint32_t>(count);
			if (la->pl == nullptr)
				return FTSTREAM_PARSER_READ_FAIL;
		}
		for (size_t i = 0; i < count; ++i)
			if (!ftstream_parser_read_uint32(pstream, &la->pl[i]))
				return FTSTREAM_PARSER_READ_FAIL;	
		return FTSTREAM_PARSER_READ_OK;
	}
	case PT_MV_CURRENCY:
	case PT_MV_I8:
	case PT_MV_SYSTIME: {
		auto la = cu_alloc<LONGLONG_ARRAY>();
		propval.pvalue = la;
		if (la == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		if (!ftstream_parser_read_uint32(pstream, &count))
			return FTSTREAM_PARSER_READ_FAIL;
		if (count * sizeof(uint64_t) > 0x10000)
			return FTSTREAM_PARSER_READ_FAIL;
		if (pstream->st_size < count * sizeof(uint64_t) + pstream->offset)
			goto CONTINUE_WAITING;
		la->count = count;
		if (0 == count) {
			la->pll = nullptr;
		} else {
			la->pll = cu_alloc<uint64_t>(count);
			if (la->pll == nullptr)
				return FTSTREAM_PARSER_READ_FAIL;
		}
		for (size_t i = 0; i < count; ++i)
			if (!ftstream_parser_read_uint64(pstream, &la->pll[i]))
				return FTSTREAM_PARSER_READ_FAIL;	
		return FTSTREAM_PARSER_READ_OK;
	}
	case PT_MV_FLOAT: {
		auto fa = cu_alloc<FLOAT_ARRAY>();
		propval.pvalue = fa;
		if (fa == nullptr ||
		    !ftstream_parser_read_uint32(pstream, &count) ||
		    count * sizeof(uint32_t) > 0x10000)
			return FTSTREAM_PARSER_READ_FAIL;
		if (pstream->st_size < count * sizeof(uint32_t) + pstream->offset)
			goto CONTINUE_WAITING;
		fa->count = count;
		if (count == 0) {
			fa->mval = nullptr;
			return FTSTREAM_PARSER_READ_OK;
		}
		fa->mval = cu_alloc<float>(count);
		if (fa->mval == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		for (size_t i = 0; i < count; ++i)
			if (!ftstream_parser_read_float(pstream, &fa->mval[i]))
				return FTSTREAM_PARSER_READ_FAIL;
		return FTSTREAM_PARSER_READ_OK;
	}
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME: {
		auto fa = cu_alloc<DOUBLE_ARRAY>();
		propval.pvalue = fa;
		if (fa == nullptr ||
		    !ftstream_parser_read_uint32(pstream, &count) ||
		    count * sizeof(uint32_t) > 0x10000)
			return FTSTREAM_PARSER_READ_FAIL;
		if (pstream->st_size < count * sizeof(uint32_t) + pstream->offset)
			goto CONTINUE_WAITING;
		fa->count = count;
		if (count == 0) {
			fa->mval = nullptr;
			return FTSTREAM_PARSER_READ_OK;
		}
		fa->mval = cu_alloc<double>(count);
		if (fa->mval == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		for (size_t i = 0; i < count; ++i)
			if (!ftstream_parser_read_double(pstream, &fa->mval[i]))
				return FTSTREAM_PARSER_READ_FAIL;
		return FTSTREAM_PARSER_READ_OK;
	}
	case PT_MV_STRING8: {
		auto sa = cu_alloc<STRING_ARRAY>();
		propval.pvalue = sa;
		if (sa == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		if (!ftstream_parser_read_uint32(pstream, &count))
			return FTSTREAM_PARSER_READ_FAIL;
		if (pstream->st_size == pstream->offset)
			goto CONTINUE_WAITING;
		sa->count = count;
		if (0 == count) {
			sa->ppstr = nullptr;
		} else {
			sa->ppstr = cu_alloc<char *>(count);
			if (sa->ppstr == nullptr)
				return FTSTREAM_PARSER_READ_FAIL;
		}
		for (size_t i = 0; i < count; ++i) {
			sa->ppstr[i] = ftstream_parser_read_string(pstream, &b_continue);
			if (sa->ppstr[i] == nullptr) {
				if (!b_continue)
					return FTSTREAM_PARSER_READ_FAIL;
				if (pstream->offset - origin_offset > 0x10000)
					return FTSTREAM_PARSER_READ_FAIL;
				goto CONTINUE_WAITING;
			}
			if (pstream->st_size == pstream->offset) {
				if (pstream->offset - origin_offset > 0x10000)
					return FTSTREAM_PARSER_READ_FAIL;
				goto CONTINUE_WAITING;
			}
		}
		return FTSTREAM_PARSER_READ_OK;
	}
	case PT_MV_UNICODE: {
		auto sa = cu_alloc<STRING_ARRAY>();
		propval.pvalue = sa;
		if (sa == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		if (!ftstream_parser_read_uint32(pstream, &count))
			return FTSTREAM_PARSER_READ_FAIL;
		if (pstream->st_size == pstream->offset)
			goto CONTINUE_WAITING;
		sa->count = count;
		if (0 == count) {
			sa->ppstr = nullptr;
		} else {
			sa->ppstr = cu_alloc<char *>(count);
			if (sa->ppstr == nullptr)
				return FTSTREAM_PARSER_READ_FAIL;
		}
		for (size_t i = 0; i < count; ++i) {
			sa->ppstr[i] = ftstream_parser_read_wstring(pstream, &b_continue);
			if (sa->ppstr[i] == nullptr) {
				if (!b_continue)
					return FTSTREAM_PARSER_READ_FAIL;
				if (pstream->offset - origin_offset > 0x10000)
					return FTSTREAM_PARSER_READ_FAIL;
				goto CONTINUE_WAITING;
			}
			if (pstream->st_size == pstream->offset) {
				if (pstream->offset - origin_offset > 0x10000)
					return FTSTREAM_PARSER_READ_FAIL;
				goto CONTINUE_WAITING;
			}
		}
		return FTSTREAM_PARSER_READ_OK;
	}
	case PT_MV_CLSID: {
		auto ga = cu_alloc<GUID_ARRAY>();
		propval.pvalue = ga;
		if (ga == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		if (!ftstream_parser_read_uint32(pstream, &count))
			return FTSTREAM_PARSER_READ_FAIL;
		if (16 * count > 0x10000)
			return FTSTREAM_PARSER_READ_FAIL;
		if (pstream->st_size < 16 * count + pstream->offset)
			goto CONTINUE_WAITING;
		ga->count = count;
		if (0 == count) {
			ga->pguid = nullptr;
		} else {
			ga->pguid = cu_alloc<GUID>(count);
			if (ga->pguid == nullptr)
				return FTSTREAM_PARSER_READ_FAIL;
		}
		for (size_t i = 0; i < count; ++i)
			if (!ftstream_parser_read_guid(pstream, &ga->pguid[i]))
				return FTSTREAM_PARSER_READ_FAIL;	
		return FTSTREAM_PARSER_READ_OK;
	}
	case PT_MV_BINARY: {
		auto ba = cu_alloc<BINARY_ARRAY>();
		propval.pvalue = ba;
		if (ba == nullptr)
			return FTSTREAM_PARSER_READ_FAIL;
		if (!ftstream_parser_read_uint32(pstream, &count))
			return FTSTREAM_PARSER_READ_FAIL;
		if (pstream->st_size == pstream->offset)
			goto CONTINUE_WAITING;
		ba->count = count;
		if (0 == count) {
			ba->pbin = nullptr;
		} else {
			ba->pbin = cu_alloc<BINARY>(ba->count);
			if (ba->pbin == nullptr) {
				ba->count = 0;
				return FTSTREAM_PARSER_READ_FAIL;
			}
		}
		for (size_t i = 0; i < count; ++i) {
			if (!ftstream_parser_read_binary(pstream,
			    ba->pbin + i, &b_continue)) {
				if (!b_continue)
					return FTSTREAM_PARSER_READ_FAIL;
				if (pstream->offset - origin_offset > 0x10000)
					return FTSTREAM_PARSER_READ_FAIL;
				goto CONTINUE_WAITING;
			}
			if (pstream->st_size == pstream->offset) {
				if (pstream->offset - origin_offset > 0x10000)
					return FTSTREAM_PARSER_READ_FAIL;
				goto CONTINUE_WAITING;
			}
		}
		return FTSTREAM_PARSER_READ_OK;
	}
	}
	return FTSTREAM_PARSER_READ_FAIL;
	
 CONTINUE_WAITING:
	pstream->offset = origin_offset;
	return FTSTREAM_PARSER_READ_CONTINUE;
}

BOOL FTSTREAM_PARSER::write_buffer(const BINARY *ptransfer_data)
{
	auto pstream = this;
	lseek(pstream->fd, 0, SEEK_END);
	auto ret = write(pstream->fd, ptransfer_data->pb, ptransfer_data->cb);
	if (ret < 0 || static_cast<size_t>(ret) != ptransfer_data->cb)
		return FALSE;	
	pstream->st_size += ptransfer_data->cb;
	return TRUE;
}

static BOOL ftstream_parser_truncate_fd(FTSTREAM_PARSER *pstream) try
{
	if (pstream->offset == 0)
		return TRUE;
	if (pstream->st_size == pstream->offset) {
		if (ftruncate(pstream->fd, 0) < 0)
			mlog(LV_ERR, "E-5317: ftruncate: %s", strerror(errno));
		if (lseek(pstream->fd, 0, SEEK_SET) < 0)
			mlog(LV_ERR, "E-5316: lseek: %s", strerror(errno));
		pstream->st_size = 0;
		pstream->offset = 0;
		return TRUE;
	}
	if (lseek(pstream->fd, pstream->offset, SEEK_SET) < 0)
		mlog(LV_WARN, "W-1425: lseek: %s", strerror(errno));
	static constexpr size_t buff_size = 0x10000;
	auto buff = std::make_unique<char[]>(buff_size);
	auto len = read(pstream->fd, buff.get(), buff_size);
	if (len <= 0)
		return FALSE;
	if (ftruncate(pstream->fd, 0) < 0)
		mlog(LV_ERR, "E-5315: ftruncate: %s", strerror(errno));
	if (lseek(pstream->fd, 0, SEEK_SET) < 0)
		mlog(LV_ERR, "E-5314: lseek: %s", strerror(errno));
	if (HXio_fullwrite(pstream->fd, buff.get(), len) < 0) {
		mlog(LV_ERR, "E-5313: write: %s", strerror(errno));
		return FALSE;
	}
	pstream->st_size = len;
	pstream->offset = 0;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1170: ENOMEM");
	return false;
}

ec_error_t fxstream_parser::process(fastupctx_object &upctx)
{
	auto pstream = this;
	uint32_t marker;
	TAGGED_PROPVAL propval{};
	
	lseek(pstream->fd, 0, SEEK_SET);
	pstream->offset = 0;
	while (true) {
		switch (ftstream_parser_read_element(*this, marker, propval)) {
		case FTSTREAM_PARSER_READ_OK: {
			if (0 != marker) {
				auto err = upctx.record_marker(marker);
				if (err != ecSuccess)
					return err;
				break;
			}
			auto proptype = PROP_TYPE(propval.proptag);
			if (proptype & FXICS_CODEPAGE_FLAG) {
				auto codepage = proptype & ~FXICS_CODEPAGE_FLAG;
				auto len = mb_to_utf8_len(static_cast<char *>(propval.pvalue));
				auto pvalue = common_util_alloc(len);
				if (pvalue == nullptr || common_util_mb_to_utf8(static_cast<cpid_t>(codepage),
				    static_cast<char *>(propval.pvalue),
				    static_cast<char *>(pvalue), len) <= 0) {
					propval.proptag = CHANGE_PROP_TYPE(propval.proptag, PT_STRING8);
				} else {
					propval.proptag = CHANGE_PROP_TYPE(propval.proptag, PT_UNICODE);
					propval.pvalue = pvalue;
				}
			}
			auto err = upctx.record_propval(&propval);
			if (err != ecSuccess)
				return err;
			break;
		}
		case FTSTREAM_PARSER_READ_CONTINUE:
			return ftstream_parser_truncate_fd(pstream) == TRUE ?
			       ecSuccess : ecRpcFailed;
		default:
			return ecRpcFailed;
		}
	}
}

std::unique_ptr<ftstream_parser> ftstream_parser::create(logon_object *plogon) try
{
	auto path = LOCAL_DISK_TMPDIR;
	if (mkdir(path, 0777) < 0 && errno != EEXIST) {
		mlog(LV_ERR, "E-1428: mkdir %s: %s", path, strerror(errno));
		return nullptr;
	}
	std::unique_ptr<ftstream_parser> pstream(new ftstream_parser);
	auto ret = pstream->fd.open_anon(path, O_RDWR | O_TRUNC);
	if (ret < 0) {
		mlog(LV_ERR, "E-1668: open_anon(%s)[%s]: %s", path,
			pstream->fd.m_path.c_str(), strerror(-ret));
		return nullptr;
	}
	pstream->plogon = plogon;
	return pstream;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1450: ENOMEM");
	return nullptr;
}
