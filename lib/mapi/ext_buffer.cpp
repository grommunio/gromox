// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <climits>
#include <cstdint>
#include <memory>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/mapidefs.h>
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/util.hpp>
#include <cstdlib>
#include <cstring>
#define TRY(expr) do { int klfdv = (expr); if (klfdv != EXT_ERR_SUCCESS) return klfdv; } while (false)

using namespace gromox;

void EXT_PULL::init(const void *pdata, uint32_t data_size,
    EXT_BUFFER_ALLOC alloc, uint32_t flags)
{
	m_udata = static_cast<const uint8_t *>(pdata);
	m_data_size = data_size;
	m_alloc = alloc;
	m_offset = 0;
	m_flags = flags;
}

int EXT_PULL::advance(uint32_t size)
{
	m_offset += size;
	if (m_offset > m_data_size)
		return EXT_ERR_BUFSIZE;
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_rpc_header_ext(RPC_HEADER_EXT *r)
{
	auto pext = this;
	TRY(pext->g_uint16(&r->version));
	TRY(pext->g_uint16(&r->flags));
	TRY(pext->g_uint16(&r->size));
	return pext->g_uint16(&r->size_actual);
}

int EXT_PULL::g_uint8(uint8_t *v)
{
	if (m_data_size < sizeof(uint8_t) ||
	    m_offset + sizeof(uint8_t) > m_data_size)
		return EXT_ERR_BUFSIZE;
	*v = m_udata[m_offset];
	m_offset += sizeof(uint8_t);
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_uint16(uint16_t *v)
{
	if (m_data_size < sizeof(uint16_t) ||
	    m_offset + sizeof(uint16_t) > m_data_size)
		return EXT_ERR_BUFSIZE;
	*v = le16p_to_cpu(&m_udata[m_offset]);
	m_offset += sizeof(uint16_t);
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_uint32(uint32_t *v)
{
	if (m_data_size < sizeof(uint32_t) ||
	    m_offset + sizeof(uint32_t) > m_data_size)
		return EXT_ERR_BUFSIZE;
	*v = le32p_to_cpu(&m_udata[m_offset]);
	m_offset += sizeof(uint32_t);
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_uint64(uint64_t *v)
{
	if (m_data_size < sizeof(uint64_t) ||
	    m_offset + sizeof(uint64_t) > m_data_size)
		return EXT_ERR_BUFSIZE;
	*v = le64p_to_cpu(&m_udata[m_offset]);
	m_offset += sizeof(uint64_t);
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_float(float *v)
{
	if (m_data_size < sizeof(float) ||
	    m_offset + sizeof(float) > m_data_size)
		return EXT_ERR_BUFSIZE;
	memcpy(v, &m_udata[m_offset], sizeof(*v));
	m_offset += sizeof(float);
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_double(double *v)
{
	if (m_data_size < sizeof(double) ||
	    m_offset + sizeof(double) > m_data_size)
		return EXT_ERR_BUFSIZE;
	memcpy(v, &m_udata[m_offset], sizeof(*v));
	m_offset += sizeof(double);
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_bool(BOOL *v)
{
	if (m_data_size < sizeof(uint8_t) ||
	    m_offset + sizeof(uint8_t) > m_data_size)
		return EXT_ERR_BUFSIZE;
	auto tmp_byte = m_udata[m_offset++];
	if (tmp_byte == 0)
		*v = FALSE;
	else if (tmp_byte == 1)
		*v = TRUE;
	else
		return EXT_ERR_FORMAT;
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_bytes(void *data, uint32_t n)
{
	if (m_data_size < n || m_offset + n > m_data_size)
		return EXT_ERR_BUFSIZE;
	memcpy(data, &m_udata[m_offset], n);
	m_offset += n;
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_guid(GUID *r)
{
	auto pext = this;
	TRY(pext->g_uint32(&r->time_low));
	TRY(pext->g_uint16(&r->time_mid));
	TRY(pext->g_uint16(&r->time_hi_and_version));
	TRY(pext->g_bytes(r->clock_seq, 2));
	TRY(pext->g_bytes(r->node, 6));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_str(char **ppstr)
{
	auto pext = this;
	if (m_offset >= m_data_size)
		return EXT_ERR_BUFSIZE;
	auto len = strnlen(&m_cdata[m_offset], m_data_size - m_offset);
	if (len + 1 > m_data_size - m_offset)
		return EXT_ERR_BUFSIZE;
	len ++;
	*ppstr = pext->anew<char>(len);
	if (*ppstr == nullptr)
		return EXT_ERR_ALLOC;
	memcpy(*ppstr, &m_udata[m_offset], len);
	return pext->advance(len);
}

int EXT_PULL::g_wstr(char **ppstr)
{
	auto pext = this;
	int i, len;
	
	if (!(m_flags & EXT_FLAG_UTF16))
		return pext->g_str(ppstr);
	if (m_offset >= m_data_size)
		return EXT_ERR_BUFSIZE;
	int max_len = m_data_size - m_offset;
	for (i = 0; i < max_len - 1; i += 2)
		if (m_udata[m_offset+i] == '\0' && m_udata[m_offset+i+1] == '\0')
			break;
	if (i >= max_len - 1)
		return EXT_ERR_BUFSIZE;
	len = i + 2; /* octets */
	/* Going from UTF-16 (2 octets) to UTF-8 (up to 4 octets) */
	*ppstr = pext->anew<char>(2 * len);
	if (*ppstr == nullptr)
		return EXT_ERR_ALLOC;
	if (!utf16le_to_utf8(&m_cdata[m_offset], len, *ppstr, 2 * len))
		return EXT_ERR_CHARCNV;
	return pext->advance(len);
}

int EXT_PULL::g_blob(DATA_BLOB *pblob)
{
	auto pext = this;
	
	if (m_offset > m_data_size)
		return EXT_ERR_BUFSIZE;
	uint32_t length = m_data_size - m_offset;
	pblob->data = pext->anew<uint8_t>(length);
	if (pblob->data == nullptr)
		return EXT_ERR_ALLOC;
	memcpy(pblob->data, &m_udata[m_offset], length);
	pblob->length = length;
	m_offset += length;
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_bin(BINARY *r)
{
	uint16_t cb;
	auto pext = this;
	
	if (m_flags & EXT_FLAG_WCOUNT) {
		TRY(pext->g_uint32(&r->cb));
	} else {
		TRY(pext->g_uint16(&cb));
		r->cb = cb;
	}
	if (0 == r->cb) {
		r->pb = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pv = m_alloc(r->cb);
	if (r->pv == nullptr) {
		r->cb = 0;
		return EXT_ERR_ALLOC;
	}
	return pext->g_bytes(r->pv, r->cb);
}

int EXT_PULL::g_sbin(BINARY *r)
{
	uint16_t cb;
	auto pext = this;
	
	TRY(pext->g_uint16(&cb));
	r->cb = cb;
	if (0 == r->cb) {
		r->pb = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pv = m_alloc(r->cb);
	if (r->pv == nullptr) {
		r->cb = 0;
		return EXT_ERR_ALLOC;
	}
	return pext->g_bytes(r->pv, r->cb);
}

int EXT_PULL::g_exbin(BINARY *r)
{
	auto pext = this;
	TRY(pext->g_uint32(&r->cb));
	if (0 == r->cb) {
		r->pb = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pv = m_alloc(r->cb);
	if (r->pv == nullptr) {
		r->cb = 0;
		return EXT_ERR_ALLOC;
	}
	return pext->g_bytes(r->pv, r->cb);
}

int EXT_PULL::g_uint16_a(SHORT_ARRAY *r)
{
	auto pext = this;
	TRY(pext->g_uint32(&r->count));
	if (0 == r->count) {
		r->ps = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ps = pext->anew<uint16_t>(r->count);
	if (NULL == r->ps) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->g_uint16(&r->ps[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_uint32_a(LONG_ARRAY *r)
{
	auto pext = this;
	TRY(pext->g_uint32(&r->count));
	if (0 == r->count) {
		r->pl = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pl = pext->anew<uint32_t>(r->count);
	if (NULL == r->pl) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->g_uint32(&r->pl[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_uint64_a(LONGLONG_ARRAY *r)
{
	auto pext = this;
	TRY(pext->g_uint32(&r->count));
	if (0 == r->count) {
		r->pll = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pll = pext->anew<uint64_t>(r->count);
	if (NULL == r->pll) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->g_uint64(&r->pll[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_uint64_sa(LONGLONG_ARRAY *r)
{
	uint16_t count;
	auto pext = this;
	
	TRY(pext->g_uint16(&count));
	r->count = count;
	if (0 == r->count) {
		r->pll = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pll = pext->anew<uint64_t>(r->count);
	if (NULL == r->pll) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->g_uint64(&r->pll[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_bin_a(BINARY_ARRAY *r)
{
	auto pext = this;
	TRY(pext->g_uint32(&r->count));
	if (0 == r->count) {
		r->pbin = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pbin = pext->anew<BINARY>(r->count);
	if (NULL == r->pbin) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i) {
		if (m_flags & EXT_FLAG_ABK) {
			uint8_t value_set;
			TRY(pext->g_uint8(&value_set));
			if (value_set == 0) {
				r->pbin[i].cb = 0;
				r->pbin[i].pb = nullptr;
				continue;
			}
		}
		TRY(pext->g_bin(&r->pbin[i]));
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_str_a(STRING_ARRAY *r)
{
	auto pext = this;
	TRY(pext->g_uint32(&r->count));
	if (0 == r->count) {
		r->ppstr = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppstr = pext->anew<char *>(r->count);
	if (NULL == r->ppstr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i) {
		if (m_flags & EXT_FLAG_ABK) {
			uint8_t value_set;
			TRY(pext->g_uint8(&value_set));
			if (value_set == 0) {
				r->ppstr[i] = nullptr;
				continue;
			}
		}
		TRY(pext->g_str(&r->ppstr[i]));
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_wstr_a(STRING_ARRAY *r)
{
	auto pext = this;
	TRY(pext->g_uint32(&r->count));
	if (0 == r->count) {
		r->ppstr = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppstr = pext->anew<char *>(r->count);
	if (NULL == r->ppstr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i) {
		if (m_flags & EXT_FLAG_ABK) {
			uint8_t value_set;
			TRY(pext->g_uint8(&value_set));
			if (value_set == 0) {
				r->ppstr[i] = nullptr;
				continue;
			}
		}
		TRY(pext->g_wstr(&r->ppstr[i]));
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_guid_a(GUID_ARRAY *r)
{
	auto pext = this;
	TRY(pext->g_uint32(&r->count));
	if (0 == r->count) {
		r->pguid = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pguid = pext->anew<GUID>(r->count);
	if (NULL == r->pguid) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->g_guid(&r->pguid[i]));
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_restriction_and_or(
	EXT_PULL *pext, RESTRICTION_AND_OR *r)
{
	auto &ext = *pext;
	uint16_t count;
	
	if (ext.m_flags & EXT_FLAG_WCOUNT) {
		TRY(pext->g_uint32(&r->count));
	} else {
		TRY(pext->g_uint16(&count));
		r->count = count;
	}
	if (0 == r->count) {
		r->pres = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pres = pext->anew<RESTRICTION>(r->count);
	if (NULL == r->pres) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->g_restriction(&r->pres[i]));
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_restriction_not(
	EXT_PULL *pext, RESTRICTION_NOT *r)
{
	return pext->g_restriction(&r->res);
}

static int ext_buffer_pull_restriction_content(
	EXT_PULL *pext, RESTRICTION_CONTENT *r)
{
	TRY(pext->g_uint32(&r->fuzzy_level));
	TRY(pext->g_uint32(&r->proptag));
	return pext->g_tagged_pv(&r->propval);
}

static int ext_buffer_pull_restriction_property(
	EXT_PULL *pext, RESTRICTION_PROPERTY *r)
{
	uint8_t relop;
	
	TRY(pext->g_uint8(&relop));
	r->relop = static_cast<enum relop>(relop);
	TRY(pext->g_uint32(&r->proptag));
	return pext->g_tagged_pv(&r->propval);
}

static int ext_buffer_pull_restriction_propcompare(
	EXT_PULL *pext, RESTRICTION_PROPCOMPARE *r)
{
	uint8_t relop;
	
	TRY(pext->g_uint8(&relop));
	r->relop = static_cast<enum relop>(relop);
	TRY(pext->g_uint32(&r->proptag1));
	return pext->g_uint32(&r->proptag2);
}

static int ext_buffer_pull_restriction_bitmask(
	EXT_PULL *pext, RESTRICTION_BITMASK *r)
{
	uint8_t relop;
	
	TRY(pext->g_uint8(&relop));
	r->bitmask_relop = static_cast<enum bm_relop>(relop);
	TRY(pext->g_uint32(&r->proptag));
	return pext->g_uint32(&r->mask);
}

static int ext_buffer_pull_restriction_size(
	EXT_PULL *pext, RESTRICTION_SIZE *r)
{
	uint8_t relop;
	
	TRY(pext->g_uint8(&relop));
	r->relop = static_cast<enum relop>(relop);
	TRY(pext->g_uint32(&r->proptag));
	return pext->g_uint32(&r->size);
}

static int ext_buffer_pull_restriction_exist(
	EXT_PULL *pext, RESTRICTION_EXIST *r)
{
	return pext->g_uint32(&r->proptag);
}

static int ext_buffer_pull_restriction_subobj(
	EXT_PULL *pext, RESTRICTION_SUBOBJ *r)
{
	TRY(pext->g_uint32(&r->subobject));
	return pext->g_restriction(&r->res);
}

static int ext_buffer_pull_restriction_comment(
	EXT_PULL *pext, RESTRICTION_COMMENT *r)
{
	uint8_t res_present;
	
	TRY(pext->g_uint8(&r->count));
	if (r->count == 0)
		return EXT_ERR_FORMAT;
	r->ppropval = pext->anew<TAGGED_PROPVAL>(r->count);
	if (NULL == r->ppropval) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->g_tagged_pv(&r->ppropval[i]));
	TRY(pext->g_uint8(&res_present));
	if (0 != res_present) {
		r->pres = pext->anew<RESTRICTION>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_restriction(r->pres);
	}
	r->pres = NULL;
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_restriction_count(
	EXT_PULL *pext, RESTRICTION_COUNT *r)
{
	TRY(pext->g_uint32(&r->count));
	return pext->g_restriction(&r->sub_res);
}

int EXT_PULL::g_restriction(RESTRICTION *r)
{
	uint8_t rt;
	auto pext = this;
	
	TRY(pext->g_uint8(&rt));
	r->rt = static_cast<res_type>(rt);
	switch (r->rt) {
	case RES_AND:
	case RES_OR:
		r->pres = pext->anew<RESTRICTION_AND_OR>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_and_or(pext, r->andor);
	case RES_NOT:
		r->pres = pext->anew<RESTRICTION_NOT>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_not(pext, r->xnot);
	case RES_CONTENT:
		r->pres = pext->anew<RESTRICTION_CONTENT>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_content(pext, r->cont);
	case RES_PROPERTY:
		r->pres = pext->anew<RESTRICTION_PROPERTY>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_property(pext, r->prop);
	case RES_PROPCOMPARE:
		r->pres = pext->anew<RESTRICTION_PROPCOMPARE>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_propcompare(pext, r->pcmp);
	case RES_BITMASK:
		r->pres = pext->anew<RESTRICTION_BITMASK>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_bitmask(pext, r->bm);
	case RES_SIZE:
		r->pres = pext->anew<RESTRICTION_SIZE>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_size(pext, r->size);
	case RES_EXIST:
		r->pres = pext->anew<RESTRICTION_EXIST>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_exist(pext, r->exist);
	case RES_SUBRESTRICTION:
		r->pres = pext->anew<RESTRICTION_SUBOBJ>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_subobj(pext, r->sub);
	case RES_COMMENT:
		r->pres = pext->anew<RESTRICTION_COMMENT>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_comment(pext, r->comment);
	case RES_COUNT:
		r->pres = pext->anew<RESTRICTION_COUNT>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_count(pext, r->count);
	case RES_NULL:
		r->pres = NULL;
		return EXT_ERR_SUCCESS;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int EXT_PULL::g_svreid(SVREID *r)
{
	uint8_t ours;
	uint16_t length;
	auto pext = this;
	
	TRY(pext->g_uint16(&length));
	TRY(pext->g_uint8(&ours));
	if (0 == ours) {
		r->folder_id = 0;
		r->message_id = 0;
		r->instance = 0;
		r->pbin = pext->anew<BINARY>();
		if (r->pbin == nullptr)
			return EXT_ERR_ALLOC;
		r->pbin->cb = length > 0 ? length - 1 : 0;
		r->pbin->pv = m_alloc(r->pbin->cb);
		if (r->pbin->pv == nullptr) {
			r->pbin->cb = 0;
			return EXT_ERR_ALLOC;
		}
		return pext->g_bytes(r->pbin->pv, r->pbin->cb);
	}
	if (length != 21)
		return EXT_ERR_FORMAT;
	r->pbin = NULL;
	TRY(pext->g_uint64(&r->folder_id));
	TRY(pext->g_uint64(&r->message_id));
	return pext->g_uint32(&r->instance);
}

int EXT_PULL::g_store_eid(STORE_ENTRYID *r)
{
	auto pext = this;
	TRY(pext->g_uint32(&r->flags));
	TRY(pext->g_bytes(r->provider_uid, 16));
	TRY(pext->g_uint8(&r->version));
	TRY(pext->g_uint8(&r->flag));
	TRY(pext->g_bytes(r->dll_name, 14));
	TRY(pext->g_uint32(&r->wrapped_flags));
	TRY(pext->g_bytes(r->wrapped_provider_uid, 16));
	TRY(pext->g_uint32(&r->wrapped_type));
	TRY(pext->g_str(&r->pserver_name));
	return pext->g_str(&r->pmailbox_dn);
}

static int ext_buffer_pull_zmovecopy_action(EXT_PULL *e, ZMOVECOPY_ACTION *r)
{
	TRY(e->g_bin(&r->store_eid));
	return e->g_bin(&r->folder_eid);
}

static int ext_buffer_pull_movecopy_action(EXT_PULL *pext, MOVECOPY_ACTION *r)
{
	uint16_t eid_size;
	
	TRY(pext->g_uint8(&r->same_store));
	TRY(pext->g_uint16(&eid_size));
	if (0 == r->same_store) {
		r->pstore_eid = pext->anew<STORE_ENTRYID>();
		if (r->pstore_eid == nullptr)
			return EXT_ERR_ALLOC;
		TRY(pext->g_store_eid(r->pstore_eid));
	} else {
		r->pstore_eid = NULL;
		TRY(pext->advance(eid_size));
	}
	if (0 != r->same_store) {
		r->pfolder_eid = pext->anew<SVREID>();
		if (r->pfolder_eid == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_svreid(static_cast<SVREID *>(r->pfolder_eid));
	} else {
		r->pfolder_eid = pext->anew<BINARY>();
		if (r->pfolder_eid == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_bin(static_cast<BINARY *>(r->pfolder_eid));
	}
}

static int ext_buffer_pull_zreply_action(EXT_PULL *e, ZREPLY_ACTION *r)
{
	TRY(e->g_bin(&r->message_eid));
	return e->g_guid(&r->template_guid);
}

static int ext_buffer_pull_reply_action(EXT_PULL *pext, REPLY_ACTION *r)
{
	TRY(pext->g_uint64(&r->template_folder_id));
	TRY(pext->g_uint64(&r->template_message_id));
	return pext->g_guid(&r->template_guid);
}

static int ext_buffer_pull_recipient_block(EXT_PULL *pext, RECIPIENT_BLOCK *r)
{
	TRY(pext->g_uint8(&r->reserved));
	TRY(pext->g_uint16(&r->count));
	if (r->count == 0)
		return EXT_ERR_FORMAT;
	r->ppropval = pext->anew<TAGGED_PROPVAL>(r->count);
	if (NULL == r->ppropval) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->g_tagged_pv(&r->ppropval[i]));
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_forwarddelegate_action(
	EXT_PULL *pext, FORWARDDELEGATE_ACTION *r)
{
	TRY(pext->g_uint16(&r->count));
	if (r->count == 0)
		return EXT_ERR_FORMAT;
	r->pblock = pext->anew<RECIPIENT_BLOCK>(r->count);
	if (NULL == r->pblock) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(ext_buffer_pull_recipient_block(pext, &r->pblock[i]));
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_action_block(EXT_PULL *pext, ACTION_BLOCK *r)
{
	auto &ext = *pext;
	uint16_t tmp_len;
	
	TRY(pext->g_uint16(&r->length));
	TRY(pext->g_uint8(&r->type));
	TRY(pext->g_uint32(&r->flavor));
	TRY(pext->g_uint32(&r->flags));
	switch (r->type) {
	case OP_MOVE:
	case OP_COPY: {
		if (pext->m_flags & EXT_FLAG_ZCORE) {
			auto mc = pext->anew<ZMOVECOPY_ACTION>();
			if (mc == nullptr)
				return EXT_ERR_ALLOC;
			r->pdata = mc;
			return ext_buffer_pull_zmovecopy_action(pext, mc);
		}
		auto mc = pext->anew<MOVECOPY_ACTION>();
		if (mc == nullptr)
			return EXT_ERR_ALLOC;
		r->pdata = mc;
		return ext_buffer_pull_movecopy_action(pext, mc);
	}
	case OP_REPLY:
	case OP_OOF_REPLY: {
		if (pext->m_flags & EXT_FLAG_ZCORE) {
			auto rp = pext->anew<ZREPLY_ACTION>();
			if (rp == nullptr)
				return EXT_ERR_ALLOC;
			r->pdata = rp;
			return ext_buffer_pull_zreply_action(pext, rp);
		}
		auto rp = pext->anew<REPLY_ACTION>();
		if (rp == nullptr)
			return EXT_ERR_ALLOC;
		r->pdata = rp;
		return ext_buffer_pull_reply_action(pext, rp);
	}
	case OP_DEFER_ACTION:
		tmp_len = r->length - sizeof(uint8_t) - 2*sizeof(uint32_t);
		r->pdata = ext.m_alloc(tmp_len);
		if (r->pdata == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_bytes(r->pdata, tmp_len);
	case OP_BOUNCE:
		r->pdata = pext->anew<uint32_t>();
		if (r->pdata == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_uint32(static_cast<uint32_t *>(r->pdata));
	case OP_FORWARD:
	case OP_DELEGATE:
		r->pdata = pext->anew<FORWARDDELEGATE_ACTION>();
		if (r->pdata == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_forwarddelegate_action(pext, static_cast<FORWARDDELEGATE_ACTION *>(r->pdata));
	case OP_TAG:
		r->pdata = pext->anew<TAGGED_PROPVAL>();
		if (r->pdata == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_tagged_pv(static_cast<TAGGED_PROPVAL *>(r->pdata));
	case OP_DELETE:
	case OP_MARK_AS_READ:
		r->pdata = NULL;
		return EXT_ERR_SUCCESS;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int EXT_PULL::g_rule_actions(RULE_ACTIONS *r)
{
	auto pext = this;
	
	TRY(pext->g_uint16(&r->count));
	if (r->count == 0)
		return EXT_ERR_FORMAT;
	r->pblock = pext->anew<ACTION_BLOCK>(r->count);
	if (NULL == r->pblock) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(ext_buffer_pull_action_block(pext, &r->pblock[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_propval(uint16_t type, void **ppval)
{
	auto pext = this;
	if (m_flags & EXT_FLAG_ABK && (type == PT_STRING8 || type == PT_UNICODE ||
	    type == PT_BINARY || (type & MV_FLAG))) {
		uint8_t value_set;
		TRY(pext->g_uint8(&value_set));
		if (value_set == 0) {
			*ppval = nullptr;
			return EXT_ERR_SUCCESS;
		} else if (value_set != 0xFF) {
			return EXT_ERR_FORMAT;
		}
	} else if ((type & MVI_FLAG) == MVI_FLAG) {
	/* convert multi-value instance into single value */
		type &= ~MVI_FLAG;
	}
	switch (type) {
	case PT_UNSPECIFIED:
		*ppval = pext->anew<TYPED_PROPVAL>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_typed_pv(static_cast<TYPED_PROPVAL *>(*ppval));
	case PT_SHORT:
		*ppval = pext->anew<uint16_t>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_uint16(static_cast<uint16_t *>(*ppval));
	case PT_LONG:
	case PT_ERROR:
		*ppval = pext->anew<uint32_t>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_uint32(static_cast<uint32_t *>(*ppval));
	case PT_FLOAT:
		*ppval = pext->anew<float>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_float(static_cast<float *>(*ppval));
	case PT_DOUBLE:
	case PT_APPTIME:
		*ppval = pext->anew<double>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_double(static_cast<double *>(*ppval));
	case PT_BOOLEAN:
		*ppval = pext->anew<uint8_t>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_uint8(static_cast<uint8_t *>(*ppval));
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME:
		*ppval = pext->anew<uint64_t>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_uint64(static_cast<uint64_t *>(*ppval));
	case PT_STRING8:
		return pext->g_str(reinterpret_cast<char **>(ppval));
	case PT_UNICODE:
		return pext->g_wstr(reinterpret_cast<char **>(ppval));
	case PT_SVREID:
		*ppval = pext->anew<SVREID>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_svreid(static_cast<SVREID *>(*ppval));
	case PT_CLSID:
		*ppval = pext->anew<GUID>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_guid(static_cast<GUID *>(*ppval));
	case PT_SRESTRICTION:
		*ppval = pext->anew<RESTRICTION>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_restriction(static_cast<RESTRICTION *>(*ppval));
	case PT_ACTIONS:
		*ppval = pext->anew<RULE_ACTIONS>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_rule_actions(static_cast<RULE_ACTIONS *>(*ppval));
	case PT_BINARY:
	case PT_OBJECT:
		*ppval = pext->anew<BINARY>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_bin(static_cast<BINARY *>(*ppval));
	case PT_MV_SHORT:
		*ppval = pext->anew<SHORT_ARRAY>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_uint16_a(static_cast<SHORT_ARRAY *>(*ppval));
	case PT_MV_LONG:
		*ppval = pext->anew<LONG_ARRAY>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_uint32_a(static_cast<LONG_ARRAY *>(*ppval));
	case PT_MV_I8:
		*ppval = pext->anew<LONGLONG_ARRAY>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_uint64_a(static_cast<LONGLONG_ARRAY *>(*ppval));
	case PT_MV_STRING8:
		*ppval = pext->anew<STRING_ARRAY>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_str_a(static_cast<STRING_ARRAY *>(*ppval));
	case PT_MV_UNICODE:
		*ppval = pext->anew<STRING_ARRAY>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_wstr_a(static_cast<STRING_ARRAY *>(*ppval));
	case PT_MV_CLSID:
		*ppval = pext->anew<GUID_ARRAY>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_guid_a(static_cast<GUID_ARRAY *>(*ppval));
	case PT_MV_BINARY:
		*ppval = pext->anew<BINARY_ARRAY>();
		if ((*ppval) == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_bin_a(static_cast<BINARY_ARRAY *>(*ppval));
	default:
		return m_flags & EXT_FLAG_ABK ? EXT_ERR_FORMAT : EXT_ERR_BAD_SWITCH;
	}
}

int EXT_PULL::g_typed_pv(TYPED_PROPVAL *r)
{
	auto pext = this;
	TRY(pext->g_uint16(&r->type));
	return pext->g_propval(r->type, &r->pvalue);
}

int EXT_PULL::g_tagged_pv(TAGGED_PROPVAL *r)
{
	auto pext = this;
	TRY(pext->g_uint32(&r->proptag));
	return pext->g_propval(PROP_TYPE(r->proptag), &r->pvalue);
}

int EXT_PULL::g_longterm(LONG_TERM_ID *r)
{
	auto pext = this;
	TRY(pext->g_guid(&r->guid));
	TRY(g_bytes(r->global_counter.ab, 6));
	return pext->g_uint16(&r->padding);
}

int EXT_PULL::g_longterm_rang(LONG_TERM_ID_RANGE *r)
{
	auto pext = this;
	TRY(pext->g_longterm(&r->min));
	return pext->g_longterm(&r->max);
}

int EXT_PULL::g_proptag_a(PROPTAG_ARRAY *r)
{
	auto pext = this;
	
	TRY(pext->g_uint16(&r->count));
	if (0 == r->count) {
		r->pproptag = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pproptag = pext->anew<uint32_t>(strange_roundup(r->count, SR_GROW_PROPTAG_ARRAY));
	if (NULL == r->pproptag) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->g_uint32(&r->pproptag[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_proptag_a(LPROPTAG_ARRAY *r)
{
	TRY(g_uint32(&r->cvalues));
	if (r->cvalues == 0) {
		r->pproptag = nullptr;
		return EXT_ERR_SUCCESS;
	}
	r->pproptag = anew<uint32_t>(strange_roundup(r->cvalues, SR_GROW_PROPTAG_ARRAY));
	if (r->pproptag == nullptr) {
		r->cvalues = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->cvalues; ++i)
		TRY(g_uint32(&r->pproptag[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_propname(PROPERTY_NAME *r)
{
	uint8_t name_size;
	auto pext = this;
	
	TRY(pext->g_uint8(&r->kind));
	TRY(pext->g_guid(&r->guid));
	r->lid = 0;
	r->pname = NULL;
	if (r->kind == MNID_ID) {
		TRY(pext->g_uint32(&r->lid));
	} else if (r->kind == MNID_STRING) {
		TRY(pext->g_uint8(&name_size));
		if (name_size < 2)
			return EXT_ERR_FORMAT;
		uint32_t offset = m_offset + name_size;
		TRY(pext->g_wstr(&r->pname));
		if (m_offset > offset)
			return EXT_ERR_FORMAT;
		m_offset = offset;
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_propname_a(PROPNAME_ARRAY *r)
{
	auto pext = this;
	
	TRY(pext->g_uint16(&r->count));
	if (0 == r->count) {
		r->ppropname = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppropname = pext->anew<PROPERTY_NAME>(r->count);
	if (NULL == r->ppropname) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->g_propname(&r->ppropname[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_propid_a(PROPID_ARRAY *r)
{
	auto pext = this;
	
	TRY(pext->g_uint16(&r->count));
	if (0 == r->count) {
		r->ppropid = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppropid = pext->anew<uint16_t>(r->count);
	if (NULL == r->ppropid) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->g_uint16(&r->ppropid[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_tpropval_a(TPROPVAL_ARRAY *r)
{
	auto pext = this;
	
	TRY(pext->g_uint16(&r->count));
	if (0 == r->count) {
		r->ppropval = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppropval = pext->anew<TAGGED_PROPVAL>(strange_roundup(r->count, SR_GROW_TAGGED_PROPVAL));
	if (NULL == r->ppropval) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->g_tagged_pv(&r->ppropval[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_tpropval_a(LTPROPVAL_ARRAY *r)
{
	TRY(g_uint32(&r->count));
	if (r->count == 0) {
		r->propval = nullptr;
		return EXT_ERR_SUCCESS;
	}
	r->propval = anew<TAGGED_PROPVAL>(strange_roundup(r->count, SR_GROW_TAGGED_PROPVAL));
	if (r->propval == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(g_tagged_pv(&r->propval[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_tarray_set(TARRAY_SET *r)
{
	auto pext = this;
	TRY(pext->g_uint32(&r->count));
	if (0 == r->count) {
		r->pparray = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pparray = pext->anew<TPROPVAL_ARRAY *>(strange_roundup(r->count, SR_GROW_TPROPVAL_ARRAY));
	if (NULL == r->pparray) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i) {
		r->pparray[i] = pext->anew<TPROPVAL_ARRAY>();
		if (r->pparray[i] == nullptr)
			return EXT_ERR_ALLOC;
		TRY(pext->g_tpropval_a(r->pparray[i]));
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_property_problem(EXT_PULL *pext, PROPERTY_PROBLEM *r)
{
	TRY(pext->g_uint16(&r->index));
	TRY(pext->g_uint32(&r->proptag));
	return pext->g_uint32(&r->err);
}

int EXT_PULL::g_problem_a(PROBLEM_ARRAY *r)
{
	auto pext = this;
	
	TRY(pext->g_uint16(&r->count));
	r->pproblem = pext->anew<PROPERTY_PROBLEM>(r->count);
	if (NULL == r->pproblem) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(ext_buffer_pull_property_problem(pext, r->pproblem + i));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_xid(uint8_t size, XID *pxid)
{
	auto pext = this;
	if (size < 17 || size > 24)
		return EXT_ERR_FORMAT;
	TRY(pext->g_guid(&pxid->guid));
	return pext->g_bytes(pxid->local_id, size - 16);
}

int EXT_PULL::g_folder_eid(FOLDER_ENTRYID *r)
{
	auto pext = this;
	TRY(pext->g_uint32(&r->flags));
	TRY(pext->g_bytes(r->provider_uid, 16));
	TRY(pext->g_uint16(&r->folder_type));
	TRY(pext->g_guid(&r->database_guid));
	TRY(g_bytes(r->global_counter.ab, 6));
	return pext->g_bytes(r->pad, 2);
}

static int ext_buffer_pull_ext_movecopy_action(
	EXT_PULL *pext, EXT_MOVECOPY_ACTION *r)
{
	uint32_t size;
	
	TRY(pext->g_uint32(&size));
	if (size == 0)
		return EXT_ERR_FORMAT;
	else
		TRY(pext->advance(size));
	TRY(pext->g_uint32(&size));
	if (size != 46)
		return EXT_ERR_FORMAT;
	return pext->g_folder_eid(&r->folder_eid);
}

int EXT_PULL::g_msg_eid(MESSAGE_ENTRYID *r)
{
	auto pext = this;
	TRY(pext->g_uint32(&r->flags));
	TRY(pext->g_bytes(r->provider_uid, 16));
	TRY(pext->g_uint16(&r->message_type));
	TRY(pext->g_guid(&r->folder_database_guid));
	TRY(g_bytes(r->folder_global_counter.ab, 6));
	TRY(pext->g_bytes(r->pad1, 2));
	TRY(pext->g_guid(&r->message_database_guid));
	TRY(g_bytes(r->message_global_counter.ab, 6));
	return pext->g_bytes(r->pad2, 2);
}

static int ext_buffer_pull_ext_reply_action(
	EXT_PULL *pext, EXT_REPLY_ACTION *r)
{
	uint32_t size;
	
	TRY(pext->g_uint32(&size));
	if (size != 70)
		return EXT_ERR_FORMAT;
	TRY(pext->g_msg_eid(&r->message_eid));
	return pext->g_guid(&r->template_guid);
}


static int ext_buffer_pull_ext_recipient_block(
	EXT_PULL *pext, EXT_RECIPIENT_BLOCK *r)
{
	TRY(pext->g_uint8(&r->reserved));
	TRY(pext->g_uint32(&r->count));
	if (r->count == 0)
		return EXT_ERR_FORMAT;
	r->ppropval = pext->anew<TAGGED_PROPVAL>(r->count);
	if (NULL == r->ppropval) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->g_tagged_pv(&r->ppropval[i]));
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_ext_forwarddelegate_action(EXT_PULL *pext,
	EXT_FORWARDDELEGATE_ACTION *r)
{
	TRY(pext->g_uint32(&r->count));
	if (r->count == 0)
		return EXT_ERR_FORMAT;
	r->pblock = pext->anew<EXT_RECIPIENT_BLOCK>(r->count);
	if (NULL == r->pblock) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(ext_buffer_pull_ext_recipient_block(pext, &r->pblock[i]));
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_ext_action_block(
	EXT_PULL *pext, EXT_ACTION_BLOCK *r)
{
	auto &ext = *pext;
	uint32_t tmp_len;
	
	TRY(pext->g_uint32(&r->length));
	TRY(pext->g_uint8(&r->type));
	TRY(pext->g_uint32(&r->flavor));
	TRY(pext->g_uint32(&r->flags));
	switch (r->type) {
	case OP_MOVE:
	case OP_COPY:
		r->pdata = pext->anew<EXT_MOVECOPY_ACTION>();
		if (r->pdata == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_ext_movecopy_action(pext, static_cast<EXT_MOVECOPY_ACTION *>(r->pdata));
	case OP_REPLY:
	case OP_OOF_REPLY:
		r->pdata = pext->anew<EXT_REPLY_ACTION>();
		if (r->pdata == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_ext_reply_action(pext, static_cast<EXT_REPLY_ACTION *>(r->pdata));
	case OP_DEFER_ACTION:
		tmp_len = r->length - sizeof(uint8_t) - sizeof(uint32_t);
		r->pdata = ext.m_alloc(tmp_len);
		if (r->pdata == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_bytes(r->pdata, tmp_len);
	case OP_BOUNCE:
		r->pdata = pext->anew<uint32_t>();
		if (r->pdata == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_uint32(static_cast<uint32_t *>(r->pdata));
	case OP_FORWARD:
	case OP_DELEGATE:
		r->pdata = pext->anew<EXT_FORWARDDELEGATE_ACTION>();
		if (r->pdata == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_ext_forwarddelegate_action(pext, static_cast<EXT_FORWARDDELEGATE_ACTION *>(r->pdata));
	case OP_TAG:
		r->pdata = pext->anew<TAGGED_PROPVAL>();
		if (r->pdata == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_tagged_pv(static_cast<TAGGED_PROPVAL *>(r->pdata));
	case OP_DELETE:
	case OP_MARK_AS_READ:
		r->pdata = NULL;
		return EXT_ERR_SUCCESS;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int EXT_PULL::g_ext_rule_actions(EXT_RULE_ACTIONS *r)
{
	auto pext = this;
	TRY(pext->g_uint32(&r->count));
	if (r->count == 0)
		return EXT_ERR_FORMAT;
	r->pblock = pext->anew<EXT_ACTION_BLOCK>(r->count);
	if (NULL == r->pblock) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(ext_buffer_pull_ext_action_block(pext, &r->pblock[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_namedprop_info(NAMEDPROPERTY_INFOMATION *r)
{
	uint32_t size;
	auto pext = this;
	
	TRY(pext->g_uint16(&r->count));
	if (0 == r->count) {
		r->ppropid = NULL;
		r->ppropname = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppropid = pext->anew<uint16_t>(r->count);
	if (NULL == r->ppropid) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	r->ppropname = pext->anew<PROPERTY_NAME>(r->count);
	if (NULL == r->ppropname) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->g_uint16(&r->ppropid[i]));
	TRY(pext->g_uint32(&size));
	uint32_t offset = m_offset + size;
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->g_propname(&r->ppropname[i]));
	if (offset < m_offset)
		return EXT_ERR_FORMAT;
	m_offset = offset;
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_flagged_pv(uint16_t type, FLAGGED_PROPVAL *r)
{
	void **ppvalue;
	auto pext = this;
	
	if (type == PT_UNSPECIFIED) {
		/* OXCDATA §2.11.6 FlaggedPropertyValueWithType */
		TRY(pext->g_uint16(&type));
		r->pvalue = pext->anew<TYPED_PROPVAL>();
		if (r->pvalue == nullptr)
			return EXT_ERR_ALLOC;
		((TYPED_PROPVAL*)r->pvalue)->type = type;
		ppvalue = &((TYPED_PROPVAL*)r->pvalue)->pvalue;
	} else {
		ppvalue = &r->pvalue;
	}
	TRY(pext->g_uint8(&r->flag));
	switch (r->flag) {
	case FLAGGED_PROPVAL_FLAG_AVAILABLE:
		return pext->g_propval(type, ppvalue);
	case FLAGGED_PROPVAL_FLAG_UNAVAILABLE:
		*ppvalue = NULL;
		return EXT_ERR_SUCCESS;
	case FLAGGED_PROPVAL_FLAG_ERROR:
		*ppvalue = pext->anew<uint32_t>();
		if (*ppvalue == nullptr)
			return EXT_ERR_ALLOC;
		return pext->g_uint32(static_cast<uint32_t *>(*ppvalue));
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int EXT_PULL::g_proprow(const PROPTAG_ARRAY *pcolumns, PROPERTY_ROW *r)
{
	auto pext = this;
	
	TRY(pext->g_uint8(&r->flag));
	r->pppropval = pext->anew<void *>(pcolumns->count);
	if (r->pppropval == nullptr)
		return EXT_ERR_ALLOC;
	if (PROPERTY_ROW_FLAG_NONE == r->flag) {
		for (size_t i = 0; i < pcolumns->count; ++i)
			TRY(pext->g_propval(PROP_TYPE(pcolumns->pproptag[i]), &r->pppropval[i]));
		return EXT_ERR_SUCCESS;
	} else if (PROPERTY_ROW_FLAG_FLAGGED == r->flag) {
		for (size_t i = 0; i < pcolumns->count; ++i) {
			r->pppropval[i] = pext->anew<FLAGGED_PROPVAL>();
			if (r->pppropval[i] == nullptr)
				return EXT_ERR_ALLOC;
			TRY(pext->g_flagged_pv(PROP_TYPE(pcolumns->pproptag[i]),
			         static_cast<FLAGGED_PROPVAL *>(r->pppropval[i])));
		}
		return EXT_ERR_SUCCESS;
	}
	return EXT_ERR_BAD_SWITCH;
}

int EXT_PULL::g_sortorder(SORT_ORDER *r)
{
	auto pext = this;
	TRY(pext->g_uint16(&r->type));
	if ((r->type & MVI_FLAG) == MV_FLAG)
		/* MV_FLAG set without MV_INSTANCE */
		return EXT_ERR_FORMAT;
	TRY(pext->g_uint16(&r->propid));
	return pext->g_uint8(&r->table_sort);
}

int EXT_PULL::g_sortorder_set(SORTORDER_SET *r)
{
	auto pext = this;
	
	TRY(pext->g_uint16(&r->count));
	TRY(pext->g_uint16(&r->ccategories));
	TRY(pext->g_uint16(&r->cexpanded));
	if (r->count == 0 || r->ccategories > r->count || r->cexpanded > r->ccategories)
		return EXT_ERR_FORMAT;
	r->psort = pext->anew<SORT_ORDER>(r->count);
	if (NULL == r->psort) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(g_sortorder(&r->psort[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_recipient_row(const PROPTAG_ARRAY *pproptags, RECIPIENT_ROW *r)
{
	uint8_t type;
	BOOL b_unicode;
	PROPTAG_ARRAY proptags;
	auto pext = this;
	
	TRY(pext->g_uint16(&r->flags));
	type = r->flags & 0x0007;
	b_unicode = FALSE;
	if (r->flags & RECIPIENT_ROW_FLAG_UNICODE)
		b_unicode = TRUE;
	r->pprefix_used = NULL;
	r->have_display_type = false;
	r->px500dn = NULL;
	if (RECIPIENT_ROW_TYPE_X500DN == type) {
		r->pprefix_used = pext->anew<uint8_t>();
		if (r->pprefix_used == nullptr)
			return EXT_ERR_ALLOC;
		TRY(pext->g_uint8(r->pprefix_used));
		TRY(pext->g_uint8(&r->display_type));
		r->have_display_type = true;
		TRY(pext->g_str(&r->px500dn));
	}
	r->pentry_id = NULL;
	r->psearch_key = NULL;
	if (RECIPIENT_ROW_TYPE_PERSONAL_DLIST1 == type ||
		RECIPIENT_ROW_TYPE_PERSONAL_DLIST2 == type) {
		r->pentry_id = pext->anew<BINARY>();
		if (r->pentry_id == nullptr)
			return EXT_ERR_ALLOC;
		TRY(pext->g_bin(r->pentry_id));
		r->psearch_key = pext->anew<BINARY>();
		if (r->psearch_key == nullptr)
			return EXT_ERR_ALLOC;
		TRY(pext->g_bin(r->psearch_key));
	}
	r->paddress_type = NULL;
	if (type == RECIPIENT_ROW_TYPE_NONE &&
	    (r->flags & RECIPIENT_ROW_FLAG_OUTOFSTANDARD))
		TRY(pext->g_str(&r->paddress_type));
	r->pmail_address = NULL;
	if (RECIPIENT_ROW_FLAG_EMAIL & r->flags) {
		if (b_unicode)
			TRY(pext->g_wstr(&r->pmail_address));
		else
			TRY(pext->g_str(&r->pmail_address));
	}
	r->pdisplay_name = NULL;
	if (r->flags & RECIPIENT_ROW_FLAG_DISPLAY) {
		if (b_unicode)
			TRY(pext->g_wstr(&r->pdisplay_name));
		else
			TRY(pext->g_str(&r->pdisplay_name));
	}
	r->psimple_name = NULL;
	if (r->flags & RECIPIENT_ROW_FLAG_SIMPLE) {
		if (b_unicode)
			TRY(pext->g_wstr(&r->psimple_name));
		else
			TRY(pext->g_str(&r->psimple_name));
	}
	r->ptransmittable_name = NULL;
	if (r->flags & RECIPIENT_ROW_FLAG_TRANSMITTABLE) {
		if (b_unicode)
			TRY(pext->g_wstr(&r->ptransmittable_name));
		else
			TRY(pext->g_str(&r->ptransmittable_name));
	}
	if (RECIPIENT_ROW_FLAG_SAME == r->flags) {
		if (r->pdisplay_name == nullptr && r->ptransmittable_name != nullptr)
			r->pdisplay_name = r->ptransmittable_name;
		else if (r->pdisplay_name != nullptr && r->ptransmittable_name == nullptr)
			r->ptransmittable_name = r->pdisplay_name;
	}
	TRY(pext->g_uint16(&r->count));
	if (r->count > pproptags->count)
		return EXT_ERR_FORMAT;
	proptags.count = r->count;
	proptags.pproptag = (uint32_t*)pproptags->pproptag;
	return pext->g_proprow(&proptags, &r->properties);
}

int EXT_PULL::g_modrcpt_row(PROPTAG_ARRAY *pproptags, MODIFYRECIPIENT_ROW *r)
{
	uint16_t row_size;
	auto pext = this;
	
	TRY(pext->g_uint32(&r->row_id));
	TRY(pext->g_uint8(&r->recipient_type));
	TRY(pext->g_uint16(&row_size));
	if (0 == row_size) {
		r->precipient_row = NULL;
		return EXT_ERR_SUCCESS;
	}
	uint32_t offset = m_offset + row_size;
	r->precipient_row = pext->anew<RECIPIENT_ROW>();
	if (r->precipient_row == nullptr)
		return EXT_ERR_ALLOC;
	TRY(g_recipient_row(pproptags, r->precipient_row));
	if (m_offset > offset)
		return EXT_ERR_FORMAT;
	m_offset = offset;
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_permission_data(PERMISSION_DATA *r)
{
	auto pext = this;
	TRY(pext->g_uint8(&r->flags));
	return pext->g_tpropval_a(&r->propvals);
}

int EXT_PULL::g_rule_data(RULE_DATA *r)
{
	auto pext = this;
	TRY(pext->g_uint8(&r->flags));
	return pext->g_tpropval_a(&r->propvals);
}

int EXT_PULL::g_abk_eid(ADDRESSBOOK_ENTRYID *r)
{
	auto pext = this;
	TRY(pext->g_uint32(&r->flags));
	TRY(pext->g_bytes(r->provider_uid, 16));
	TRY(pext->g_uint32(&r->version));
	TRY(pext->g_uint32(&r->type));
	return pext->g_str(&r->px500dn);
}

int EXT_PULL::g_oneoff_eid(ONEOFF_ENTRYID *r)
{
	auto pext = this;
	TRY(pext->g_uint32(&r->flags));
	TRY(pext->g_bytes(r->provider_uid, 16));
	TRY(pext->g_uint16(&r->version));
	TRY(pext->g_uint16(&r->ctrl_flags));
	if (r->ctrl_flags & CTRL_FLAG_UNICODE) {
		TRY(pext->g_wstr(&r->pdisplay_name));
		TRY(pext->g_wstr(&r->paddress_type));
		return pext->g_wstr(&r->pmail_address);
	} else {
		TRY(pext->g_str(&r->pdisplay_name));
		TRY(pext->g_str(&r->paddress_type));
		return pext->g_str(&r->pmail_address);
	}
}

int EXT_PULL::g_oneoff_a(ONEOFF_ARRAY *r)
{
	uint32_t bytes;
	uint8_t pad_len;
	auto pext = this;
	
	TRY(pext->g_uint32(&r->count));
	r->pentry_id = pext->anew<ONEOFF_ENTRYID>(r->count);
	if (NULL == r->pentry_id) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	TRY(pext->g_uint32(&bytes));
	uint32_t offset = m_offset + bytes;
	for (size_t i = 0; i < r->count; ++i) {
		TRY(pext->g_uint32(&bytes));
		uint32_t offset2 = m_offset + bytes;
		TRY(pext->g_oneoff_eid(&r->pentry_id[i]));
		if (m_offset > offset2)
			return EXT_ERR_FORMAT;
		m_offset = offset2;
		pad_len = ((bytes + 3) & ~3) - bytes;
		TRY(pext->advance(pad_len));
	}
	if (m_offset > offset)
		return EXT_ERR_FORMAT;
	m_offset = offset;
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_eid_a(EID_ARRAY *r)
{
	auto pext = this;
	TRY(pext->g_uint32(&r->count));
	if (0 == r->count) {
		r->pids = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pids = pext->anew<uint64_t>(r->count);
	if (NULL == r->pids) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->g_uint64(&r->pids[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_systime(SYSTEMTIME *r)
{
	auto pext = this;
	TRY(pext->g_int16(&r->year));
	TRY(pext->g_int16(&r->month));
	TRY(pext->g_int16(&r->dayofweek));
	TRY(pext->g_int16(&r->day));
	TRY(pext->g_int16(&r->hour));
	TRY(pext->g_int16(&r->minute));
	TRY(pext->g_int16(&r->second));
	return pext->g_int16(&r->milliseconds);
}

int EXT_PULL::g_tzstruct(TIMEZONESTRUCT *r)
{
	auto pext = this;
	TRY(pext->g_int32(&r->bias));
	TRY(pext->g_int32(&r->standardbias));
	TRY(pext->g_int32(&r->daylightbias));
	TRY(pext->g_int16(&r->standardyear));
	TRY(pext->g_systime(&r->standarddate));
	TRY(pext->g_int16(&r->daylightyear));
	return pext->g_systime(&r->daylightdate);
}

static int ext_buffer_pull_tzrule(EXT_PULL *pext, TZRULE *r)
{
	TRY(pext->g_uint8(&r->major));
	TRY(pext->g_uint8(&r->minor));
	TRY(pext->g_uint16(&r->reserved));
	TRY(pext->g_uint16(&r->flags));
	TRY(pext->g_int16(&r->year));
	TRY(pext->g_bytes(r->x, 14));
	TRY(pext->g_int32(&r->bias));
	TRY(pext->g_int32(&r->standardbias));
	TRY(pext->g_int32(&r->daylightbias));
	TRY(pext->g_systime(&r->standarddate));
	return pext->g_systime(&r->daylightdate);
}

int EXT_PULL::g_tzdef(TIMEZONEDEFINITION *r)
{
	uint16_t cbheader;
	char tmp_buff[262];
	uint16_t cchkeyname;
	char tmp_buff1[1024];
	auto pext = this;
	
	TRY(pext->g_uint8(&r->major));
	TRY(pext->g_uint8(&r->minor));
	TRY(pext->g_uint16(&cbheader));
	if (cbheader > 266)
		return EXT_ERR_FORMAT;
	TRY(pext->g_uint16(&r->reserved));
	TRY(pext->g_uint16(&cchkeyname));
	if (cbheader != 6 + 2 * cchkeyname)
		return EXT_ERR_FORMAT;
	memset(tmp_buff, 0, sizeof(tmp_buff));
	TRY(pext->g_bytes(tmp_buff, cbheader - 6));
	if (!utf16le_to_utf8(tmp_buff, cbheader - 4, tmp_buff1, arsizeof(tmp_buff1)))
		return EXT_ERR_CHARCNV;
	r->keyname = pext->anew<char>(strlen(tmp_buff1) + 1);
	if (r->keyname == nullptr)
		return EXT_ERR_ALLOC;
	strcpy(r->keyname, tmp_buff1);
	TRY(pext->g_uint16(&r->crules));
	r->prules = pext->anew<TZRULE>(r->crules);
	if (NULL == r->prules) {
		r->crules = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->crules; ++i)
		TRY(ext_buffer_pull_tzrule(pext, &r->prules[i]));
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_patterntypespecific(EXT_PULL *pext,
    uint16_t patterntype, PATTERNTYPE_SPECIFIC *r)
{
	switch (patterntype) {
	case PATTERNTYPE_DAY:
		/* do nothing */
		return EXT_ERR_SUCCESS;
	case PATTERNTYPE_WEEK:
		return pext->g_uint32(&r->weekrecur);
	case PATTERNTYPE_MONTH:
	case PATTERNTYPE_MONTHEND:
	case PATTERNTYPE_HJMONTH:
	case PATTERNTYPE_HJMONTHEND:
		return pext->g_uint32(&r->dayofmonth);
	case PATTERNTYPE_MONTHNTH:
	case PATTERNTYPE_HJMONTHNTH:
		TRY(pext->g_uint32(&r->monthnth.weekrecur));
		return pext->g_uint32(&r->monthnth.recurnum);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

static int ext_buffer_pull_recurrencepattern(EXT_PULL *pext, RECURRENCE_PATTERN *r)
{
	TRY(pext->g_uint16(&r->readerversion));
	TRY(pext->g_uint16(&r->writerversion));
	TRY(pext->g_uint16(&r->recurfrequency));
	TRY(pext->g_uint16(&r->patterntype));
	TRY(pext->g_uint16(&r->calendartype));
	TRY(pext->g_uint32(&r->firstdatetime));
	TRY(pext->g_uint32(&r->period));
	TRY(pext->g_uint32(&r->slidingflag));
	TRY(ext_buffer_pull_patterntypespecific(pext, r->patterntype, &r->pts));
	TRY(pext->g_uint32(&r->endtype));
	TRY(pext->g_uint32(&r->occurrencecount));
	TRY(pext->g_uint32(&r->firstdow));
	TRY(pext->g_uint32(&r->deletedinstancecount));
	if (0 == r->deletedinstancecount) {
		r->pdeletedinstancedates = NULL;
	} else {
		r->pdeletedinstancedates = pext->anew<uint32_t>(r->deletedinstancecount);
		if (NULL == r->pdeletedinstancedates) {
			r->deletedinstancecount = 0;
			return EXT_ERR_ALLOC;
		}
	}
	for (size_t i = 0; i < r->deletedinstancecount; ++i)
		TRY(pext->g_uint32(&r->pdeletedinstancedates[i]));
	TRY(pext->g_uint32(&r->modifiedinstancecount));
	if (0 == r->modifiedinstancecount) {
		r->pmodifiedinstancedates = NULL;
	} else {
		r->pmodifiedinstancedates = pext->anew<uint32_t>(r->modifiedinstancecount);
		if (NULL == r->pmodifiedinstancedates) {
			r->modifiedinstancecount = 0;
			return EXT_ERR_ALLOC;
		}
	}
	for (size_t i = 0; i < r->modifiedinstancecount; ++i)
		TRY(pext->g_uint32(&r->pmodifiedinstancedates[i]));
	TRY(pext->g_uint32(&r->startdate));
	return pext->g_uint32(&r->enddate);
}

static int ext_buffer_pull_exceptioninfo(EXT_PULL *pext, EXCEPTIONINFO *r)
{
	uint16_t tmp_len;
	uint16_t tmp_len2;
	
	TRY(pext->g_uint32(&r->startdatetime));
	TRY(pext->g_uint32(&r->enddatetime));
	TRY(pext->g_uint32(&r->originalstartdate));
	TRY(pext->g_uint16(&r->overrideflags));
	if (r->overrideflags & OVERRIDEFLAG_SUBJECT) {
		TRY(pext->g_uint16(&tmp_len));
		TRY(pext->g_uint16(&tmp_len2));
		if (tmp_len != tmp_len2 + 1)
			return EXT_ERR_FORMAT;
		r->subject = pext->anew<char>(tmp_len);
		if (r->subject == nullptr)
			return EXT_ERR_ALLOC;
		TRY(pext->g_bytes(r->subject, tmp_len2));
		r->subject[tmp_len2] = '\0';
	}
	if (r->overrideflags & OVERRIDEFLAG_MEETINGTYPE)
		TRY(pext->g_uint32(&r->meetingtype));
	if (r->overrideflags & OVERRIDEFLAG_REMINDERDELTA)
		TRY(pext->g_uint32(&r->reminderdelta));
	if (r->overrideflags & OVERRIDEFLAG_REMINDER)
		TRY(pext->g_uint32(&r->reminderset));
	if (r->overrideflags & OVERRIDEFLAG_LOCATION) {
		TRY(pext->g_uint16(&tmp_len));
		TRY(pext->g_uint16(&tmp_len2));
		if (tmp_len != tmp_len2 + 1)
			return EXT_ERR_FORMAT;
		r->location = pext->anew<char>(tmp_len);
		if (r->location == nullptr)
			return EXT_ERR_ALLOC;
		TRY(pext->g_bytes(r->location, tmp_len2));
		r->location[tmp_len2] = '\0';
	}
	if (r->overrideflags & OVERRIDEFLAG_BUSYSTATUS)
		TRY(pext->g_uint32(&r->busystatus));
	if (r->overrideflags & OVERRIDEFLAG_ATTACHMENT)
		TRY(pext->g_uint32(&r->attachment));
	if (r->overrideflags & OVERRIDEFLAG_SUBTYPE)
		TRY(pext->g_uint32(&r->subtype));
	if (r->overrideflags & OVERRIDEFLAG_APPTCOLOR)
		TRY(pext->g_uint32(&r->appointmentcolor));
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_changehighlight(
	EXT_PULL *pext, CHANGEHIGHLIGHT *r)
{
	TRY(pext->g_uint32(&r->size));
	TRY(pext->g_uint32(&r->value));
	if (r->size < sizeof(uint32_t)) {
		return EXT_ERR_FORMAT;
	} else if (sizeof(uint32_t) == r->size) {
		r->preserved = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->preserved = pext->anew<uint8_t>(r->size - sizeof(uint32_t));
	if (NULL == r->preserved) {
		r->size = 0;
		return EXT_ERR_ALLOC;
	}
	return pext->g_bytes(r->preserved, r->size - sizeof(uint32_t));
}

static int ext_buffer_pull_extendedexception(
	EXT_PULL *pext, uint32_t writerversion2,
	uint16_t overrideflags, EXTENDEDEXCEPTION *r)
{
	int string_len;
	uint16_t tmp_len;
	
	if (writerversion2 >= 0x00003009)
		TRY(ext_buffer_pull_changehighlight(pext, &r->changehighlight));
	TRY(pext->g_uint32(&r->reservedblockee1size));
	if (0 == r->reservedblockee1size) {
		r->preservedblockee1 = NULL;
	} else {
		r->preservedblockee1 = pext->anew<uint8_t>(r->reservedblockee1size);
		if (NULL == r->preservedblockee1) {
			r->reservedblockee1size = 0;
			return EXT_ERR_ALLOC;
		}
		TRY(pext->g_bytes(r->preservedblockee1, r->reservedblockee1size));
	}
	if ((overrideflags & OVERRIDEFLAG_LOCATION) ||
		(overrideflags & OVERRIDEFLAG_SUBJECT)) {
		TRY(pext->g_uint32(&r->startdatetime));
		TRY(pext->g_uint32(&r->enddatetime));
		TRY(pext->g_uint32(&r->originalstartdate));
	}
	if (overrideflags & OVERRIDEFLAG_SUBJECT) {
		TRY(pext->g_uint16(&tmp_len));
		tmp_len *= 2;
		std::unique_ptr<char[]> pbuff;
		try {
			pbuff = std::make_unique<char[]>(3 * (tmp_len + 2));
		} catch (const std::bad_alloc &) {
			return EXT_ERR_ALLOC;
		}
		TRY(pext->g_bytes(pbuff.get(), tmp_len));
		pbuff[tmp_len ++] = '\0';
		pbuff[tmp_len ++] = '\0';
		if (!utf16le_to_utf8(pbuff.get(), tmp_len, &pbuff[tmp_len], 2 * tmp_len))
			return EXT_ERR_CHARCNV;
		string_len = strlen(&pbuff[tmp_len]);
		r->subject = pext->anew<char>(string_len + 1);
		if (r->subject == nullptr)
			return EXT_ERR_ALLOC;
		strcpy(r->subject, &pbuff[tmp_len]);
	}
	if (overrideflags & OVERRIDEFLAG_LOCATION) {
		TRY(pext->g_uint16(&tmp_len));
		tmp_len *= 2;
		std::unique_ptr<char[]> pbuff;
		try {
			pbuff = std::make_unique<char[]>(3 * (tmp_len + 2));
		} catch (const std::bad_alloc &) {
			return EXT_ERR_ALLOC;
		}
		TRY(pext->g_bytes(pbuff.get(), tmp_len));
		pbuff[tmp_len ++] = '\0';
		pbuff[tmp_len ++] = '\0';
		if (!utf16le_to_utf8(pbuff.get(), tmp_len, &pbuff[tmp_len], 2 * tmp_len))
			return EXT_ERR_CHARCNV;
		string_len = strlen(&pbuff[tmp_len]);
		r->location = pext->anew<char>(string_len + 1);
		if (r->location == nullptr)
			return EXT_ERR_ALLOC;
		strcpy(r->location, &pbuff[tmp_len]);
	}
	if ((overrideflags & OVERRIDEFLAG_LOCATION) ||
		(overrideflags & OVERRIDEFLAG_SUBJECT)) {
		TRY(pext->g_uint32(&r->reservedblockee2size));
		if (0 == r->reservedblockee2size) {
			r->preservedblockee2 = NULL;
		} else {
			r->preservedblockee2 = pext->anew<uint8_t>(r->reservedblockee2size);
			if (NULL == r->preservedblockee2) {
				r->reservedblockee2size = 0;
				return EXT_ERR_ALLOC;
			}
			TRY(pext->g_bytes(r->preservedblockee2, r->reservedblockee2size));
		}
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_apptrecpat(APPOINTMENT_RECUR_PAT *r)
{
	auto pext = this;
	
	TRY(ext_buffer_pull_recurrencepattern(this, &r->recur_pat));
	TRY(pext->g_uint32(&r->readerversion2));
	TRY(pext->g_uint32(&r->writerversion2));
	TRY(pext->g_uint32(&r->starttimeoffset));
	TRY(pext->g_uint32(&r->endtimeoffset));
	TRY(pext->g_uint16(&r->exceptioncount));
	if (0 == r->exceptioncount) {
		r->pexceptioninfo = NULL;
		r->pextendedexception = NULL;
	} else {
		r->pexceptioninfo = pext->anew<EXCEPTIONINFO>(r->exceptioncount);
		if (NULL == r->pexceptioninfo) {
			r->exceptioncount = 0;
			return EXT_ERR_ALLOC;
		}
		r->pextendedexception = pext->anew<EXTENDEDEXCEPTION>(r->exceptioncount);
		if (NULL == r->pextendedexception) {
			r->exceptioncount = 0;
			return EXT_ERR_ALLOC;
		}
	}
	for (size_t i = 0; i < r->exceptioncount; ++i)
		TRY(ext_buffer_pull_exceptioninfo(pext, &r->pexceptioninfo[i]));
	TRY(pext->g_uint32(&r->reservedblock1size));
	if (0 == r->reservedblock1size) {
		r->preservedblock1 = NULL;
	} else {
		r->preservedblock1 = pext->anew<uint8_t>(r->reservedblock1size);
		if (NULL == r->preservedblock1) {
			r->reservedblock1size = 0;
			return EXT_ERR_ALLOC;
		}
		TRY(pext->g_bytes(r->preservedblock1, r->reservedblock1size));
	}
	for (size_t i = 0; i < r->exceptioncount; ++i)
		TRY(ext_buffer_pull_extendedexception(pext, r->writerversion2, r->pexceptioninfo[i].overrideflags, &r->pextendedexception[i]));
	TRY(pext->g_uint32(&r->reservedblock2size));
	if (0 == r->reservedblock2size) {
		r->preservedblock2 = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->preservedblock2 = pext->anew<uint8_t>(r->reservedblock2size);
	if (NULL == r->preservedblock2) {
		r->reservedblock2size = 0;
		return EXT_ERR_ALLOC;
	}
	return pext->g_bytes(r->preservedblock2, r->reservedblock2size);
}

int EXT_PULL::g_goid(GLOBALOBJECTID *r)
{
	uint8_t yh;
	uint8_t yl;
	auto pext = this;
	
	TRY(pext->g_bytes(r->arrayid, 16));
	TRY(pext->g_uint8(&yh));
	TRY(pext->g_uint8(&yl));
	r->year = ((uint16_t)yh) << 8 | yl;
	TRY(pext->g_uint8(&r->month));
	TRY(pext->g_uint8(&r->day));
	TRY(pext->g_uint64(&r->creationtime));
	TRY(pext->g_bytes(r->x, 8));
	return pext->g_exbin(&r->data);
}

static int ext_buffer_pull_attachment_list(EXT_PULL *pext, ATTACHMENT_LIST *r)
{
	int i;
	uint8_t tmp_byte;
	
	TRY(pext->g_uint16(&r->count));
	r->pplist = pext->anew<ATTACHMENT_CONTENT *>(strange_roundup(r->count, SR_GROW_ATTACHMENT_CONTENT));
	if (NULL == r->pplist) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		r->pplist[i] = pext->anew<ATTACHMENT_CONTENT>();
		if (r->pplist[i] == nullptr)
			return EXT_ERR_ALLOC;
		TRY(pext->g_tpropval_a(&r->pplist[i]->proplist));
		TRY(pext->g_uint8(&tmp_byte));
		if (0 != tmp_byte) {
			r->pplist[i]->pembedded = pext->anew<MESSAGE_CONTENT>();
			if (r->pplist[i]->pembedded == nullptr)
				return EXT_ERR_ALLOC;
			TRY(pext->g_msgctnt(r->pplist[i]->pembedded));
		} else {
			r->pplist[i]->pembedded = NULL;
		}
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_msgctnt(MESSAGE_CONTENT *r)
{
	uint8_t tmp_byte;
	auto pext = this;
	
	TRY(pext->g_tpropval_a(&r->proplist));
	TRY(pext->g_uint8(&tmp_byte));
	if (0 != tmp_byte) {
		r->children.prcpts = pext->anew<TARRAY_SET>();
		if (r->children.prcpts == nullptr)
			return EXT_ERR_ALLOC;
		TRY(pext->g_tarray_set(r->children.prcpts));
	} else {
		r->children.prcpts = NULL;
	}
	TRY(pext->g_uint8(&tmp_byte));
	if (0 != tmp_byte) {
		r->children.pattachments = pext->anew<ATTACHMENT_LIST>();
		if (r->children.pattachments == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_attachment_list(
				pext, r->children.pattachments);
	}
	r->children.pattachments = NULL;
	return EXT_ERR_SUCCESS;
}

BOOL EXT_PUSH::init(void *pdata, uint32_t alloc_size,
    uint32_t flags, const EXT_BUFFER_MGT *mgt)
{
	auto pext = this;
	const EXT_BUFFER_MGT default_mgt = {malloc, realloc, free};
	m_mgt = mgt != nullptr ? *mgt : default_mgt;
	if (NULL == pdata) {
		pext->b_alloc = TRUE;
		m_alloc_size = 8192;
		m_udata = static_cast<uint8_t *>(m_mgt.alloc(m_alloc_size));
		if (m_udata == nullptr) {
			m_alloc_size = 0;
			return FALSE;
		}
	} else {
		pext->b_alloc = FALSE;
		m_udata = static_cast<uint8_t *>(pdata);
		m_alloc_size = alloc_size;
	}
	m_offset = 0;
	m_flags = flags;
	return TRUE;
}

EXT_PUSH::~EXT_PUSH()
{
	if (b_alloc)
		m_mgt.free(m_udata);
}

int EXT_PUSH::p_rpchdr(const RPC_HEADER_EXT *r)
{
	auto pext = this;
	TRY(pext->p_uint16(r->version));
	TRY(pext->p_uint16(r->flags));
	TRY(pext->p_uint16(r->size));
	return pext->p_uint16(r->size_actual);
}

/* FALSE: overflow, TRUE: not overflow */
BOOL EXT_PUSH::check_ovf(uint32_t extra_size)
{
	auto alloc_size = extra_size + m_offset;
	if (m_alloc_size >= alloc_size)
		return TRUE;
	if (!b_alloc)
		return FALSE;
	if (alloc_size < m_alloc_size * 2)
		/* Exponential growth policy, needed to reach amortized linear time (like std::string) */
		alloc_size = m_alloc_size * 2;
	auto pdata = static_cast<uint8_t *>(m_mgt.realloc(m_udata, alloc_size));
	if (pdata == nullptr)
		return FALSE;
	m_udata = pdata;
	m_alloc_size = alloc_size;
	return TRUE;
}

int EXT_PUSH::advance(uint32_t size)
{
	auto pext = this;
	if (!pext->check_ovf(size))
		return EXT_ERR_BUFSIZE;
	m_offset += size;
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_bytes(const void *pdata, uint32_t n)
{
	auto pext = this;
	if (!pext->check_ovf(n))
		return EXT_ERR_BUFSIZE;
	memcpy(&m_udata[m_offset], pdata, n);
	m_offset += n;
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_uint8(uint8_t v)
{
	auto pext = this;
	if (!pext->check_ovf(sizeof(uint8_t)))
		return EXT_ERR_BUFSIZE;
	m_udata[m_offset] = v;
	m_offset += sizeof(uint8_t);
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_uint16(uint16_t v)
{
	auto pext = this;
	if (!pext->check_ovf(sizeof(uint16_t)))
		return EXT_ERR_BUFSIZE;
	cpu_to_le16p(&m_udata[m_offset], v);
	m_offset += sizeof(uint16_t);
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_uint32(uint32_t v)
{
	auto pext = this;
	if (!pext->check_ovf(sizeof(uint32_t)))
		return EXT_ERR_BUFSIZE;
	cpu_to_le32p(&m_udata[m_offset], v);
	m_offset += sizeof(uint32_t);
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_uint64(uint64_t v)
{
	auto pext = this;
	if (!pext->check_ovf(sizeof(uint64_t)))
		return EXT_ERR_BUFSIZE;
	cpu_to_le64p(&m_udata[m_offset], v);
	m_offset += sizeof(uint64_t);
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_float(float v)
{
	auto pext = this;
	if (!pext->check_ovf(sizeof(float)))
		return EXT_ERR_BUFSIZE;
	memcpy(&m_udata[m_offset], &v, sizeof(v));
	m_offset += sizeof(float);
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_double(double v)
{
	auto pext = this;
	static_assert(sizeof(v) == 8 && CHAR_BIT == 8, "");
	if (!pext->check_ovf(sizeof(double)))
		return EXT_ERR_BUFSIZE;
	memcpy(&m_udata[m_offset], &v, sizeof(v));
	m_offset += sizeof(double);
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_bool(BOOL v)
{
	auto pext = this;
	uint8_t tmp_byte;
	
	if (v)
		tmp_byte = 1;
	else if (!v)
		tmp_byte = 0;
	else
		return EXT_ERR_FORMAT;
	if (!pext->check_ovf(sizeof(uint8_t)))
		return EXT_ERR_BUFSIZE;
	m_udata[m_offset] = tmp_byte;
	m_offset += sizeof(uint8_t);
	return EXT_ERR_SUCCESS;
	
}

int EXT_PUSH::p_blob(DATA_BLOB blob)
{
	auto pext = this;
	return pext->p_bytes(blob.data, blob.length);
}

int EXT_PUSH::p_bin(const BINARY *r)
{
	auto pext = this;
	if (m_flags & EXT_FLAG_WCOUNT) {
		TRY(pext->p_uint32(r->cb));
	} else {
		if (r->cb > 0xFFFF)
			return EXT_ERR_FORMAT;
		TRY(pext->p_uint16(r->cb));
	}
	if (r->cb == 0)
		return EXT_ERR_SUCCESS;
	return pext->p_bytes(r->pb, r->cb);
}

int EXT_PUSH::p_bin_s(const BINARY *r)
{
	auto pext = this;
	if (r->cb > 0xFFFF)
		return EXT_ERR_FORMAT;
	TRY(pext->p_uint16(r->cb));
	if (r->cb == 0)
		return EXT_ERR_SUCCESS;
	return pext->p_bytes(r->pb, r->cb);
}

int EXT_PUSH::p_bin_ex(const BINARY *r)
{
	auto pext = this;
	TRY(pext->p_uint32(r->cb));
	if (r->cb == 0)
		return EXT_ERR_SUCCESS;
	return pext->p_bytes(r->pb, r->cb);
}

int EXT_PUSH::p_guid(const GUID *r)
{
	auto pext = this;
	TRY(pext->p_uint32(r->time_low));
	TRY(pext->p_uint16(r->time_mid));
	TRY(pext->p_uint16(r->time_hi_and_version));
	TRY(pext->p_bytes(r->clock_seq, 2));
	return pext->p_bytes(r->node, 6);
}

int EXT_PUSH::p_str(const char *pstr)
{
	auto pext = this;
	size_t len = strlen(pstr);
	if (m_flags & EXT_FLAG_TBLLMT) {
		if (len > 509) {
			TRY(pext->p_bytes(pstr, 509));
			return pext->p_uint8(0);
		}
	}
	return pext->p_bytes(pstr, len + 1);
}

int EXT_PUSH::p_wstr(const char *pstr)
{
	auto pext = this;
	int len;
	
	if (!(m_flags & EXT_FLAG_UTF16))
		return pext->p_str(pstr);
	len = 2*strlen(pstr) + 2;
	std::unique_ptr<char[]> pbuff;
	try {
		pbuff = std::make_unique<char[]>(len);
	} catch (const std::bad_alloc &) {
		return EXT_ERR_ALLOC;
	}
	len = utf8_to_utf16le(pstr, pbuff.get(), len);
	if (len < 2) {
		pbuff[0] = '\0';
		pbuff[1] = '\0';
		len = 2;
	}
	if (m_flags & EXT_FLAG_TBLLMT) {
		if (len > 510) {
			len = 510;
			pbuff[508] = '\0';
			pbuff[509] = '\0';
		}
	}
	return pext->p_bytes(pbuff.get(), len);
}

int EXT_PUSH::p_uint16_a(const SHORT_ARRAY *r)
{
	auto pext = this;
	TRY(pext->p_uint32(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->p_uint16(r->ps[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_uint32_a(const LONG_ARRAY *r)
{
	auto pext = this;
	TRY(pext->p_uint32(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->p_uint32(r->pl[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_uint64_a(const LONGLONG_ARRAY *r)
{
	auto pext = this;
	TRY(pext->p_uint32(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->p_uint64(r->pll[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_uint64_sa(const LONGLONG_ARRAY *r)
{
	auto pext = this;
	if (r->count > 0xFFFF)
		return EXT_ERR_FORMAT;
	TRY(pext->p_uint16(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->p_uint64(r->pll[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_bin_a(const BINARY_ARRAY *r)
{
	auto pext = this;
	TRY(pext->p_uint32(r->count));
	for (size_t i = 0; i < r->count; ++i) {
		if (m_flags & EXT_FLAG_ABK) {
			if (r->pbin[i].cb == 0) {
				TRY(pext->p_uint8(0));
				continue;
			}
			TRY(pext->p_uint8(0xFF));
		}
		TRY(pext->p_bin(&r->pbin[i]));
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_str_a(const STRING_ARRAY *r)
{
	auto pext = this;
	TRY(pext->p_uint32(r->count));
	for (size_t i = 0; i < r->count; ++i) {
		if (m_flags & EXT_FLAG_ABK) {
			if (r->ppstr[i] == nullptr) {
				TRY(pext->p_uint8(0));
				continue;
			}
			TRY(pext->p_uint8(0xFF));
		}
		TRY(pext->p_str(r->ppstr[i]));
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_wstr_a(const STRING_ARRAY *r)
{
	auto pext = this;
	TRY(pext->p_uint32(r->count));
	for (size_t i = 0; i < r->count; ++i) {
		if (m_flags & EXT_FLAG_ABK) {
			if (r->ppstr[i] == nullptr) {
				TRY(pext->p_uint8(0));
				continue;
			}
			TRY(pext->p_uint8(0xFF));
		}
		TRY(pext->p_wstr(r->ppstr[i]));
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_guid_a(const GUID_ARRAY *r)
{
	auto pext = this;
	TRY(pext->p_uint32(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->p_guid(&r->pguid[i]));
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_restriction_and_or(
	EXT_PUSH *pext, const RESTRICTION_AND_OR *r)
{
	auto &ext = *pext;
	if (ext.m_flags & EXT_FLAG_WCOUNT)
		TRY(pext->p_uint32(r->count));
	else
		TRY(pext->p_uint16(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->p_restriction(&r->pres[i]));
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_restriction_not(
	EXT_PUSH *pext, const RESTRICTION_NOT *r)
{
	return pext->p_restriction(&r->res);
}

static int ext_buffer_push_restriction_content(
	EXT_PUSH *pext, const RESTRICTION_CONTENT *r)
{
	TRY(pext->p_uint32(r->fuzzy_level));
	TRY(pext->p_uint32(r->proptag));
	return pext->p_tagged_pv(&r->propval);
}

static int ext_buffer_push_restriction_property(
	EXT_PUSH *pext, const RESTRICTION_PROPERTY *r)
{
	TRY(pext->p_uint8(r->relop));
	TRY(pext->p_uint32(r->proptag));
	return pext->p_tagged_pv(&r->propval);
}

static int ext_buffer_push_restriction_propcompare(
	EXT_PUSH *pext, const RESTRICTION_PROPCOMPARE *r)
{
	TRY(pext->p_uint8(r->relop));
	TRY(pext->p_uint32(r->proptag1));
	return pext->p_uint32(r->proptag2);
}

static int ext_buffer_push_restriction_bitmask(
	EXT_PUSH *pext, const RESTRICTION_BITMASK *r)
{
	TRY(pext->p_uint8(r->bitmask_relop));
	TRY(pext->p_uint32(r->proptag));
	return pext->p_uint32(r->mask);
}

static int ext_buffer_push_restriction_size(
	EXT_PUSH *pext, const RESTRICTION_SIZE *r)
{
	TRY(pext->p_uint8(r->relop));
	TRY(pext->p_uint32(r->proptag));
	return pext->p_uint32(r->size);
}

static int ext_buffer_push_restriction_exist(
	EXT_PUSH *pext, const RESTRICTION_EXIST *r)
{
	return pext->p_uint32(r->proptag);
}

static int ext_buffer_push_restriction_subobj(
	EXT_PUSH *pext, const RESTRICTION_SUBOBJ *r)
{
	TRY(pext->p_uint32(r->subobject));
	return pext->p_restriction(&r->res);
}

static int ext_buffer_push_restriction_comment(
	EXT_PUSH *pext, const RESTRICTION_COMMENT *r)
{
	if (r->count == 0)
		return EXT_ERR_FORMAT;
	TRY(pext->p_uint8(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->p_tagged_pv(&r->ppropval[i]));
	if (NULL != r->pres) {
		TRY(pext->p_uint8(1));
		return pext->p_restriction(r->pres);
	}
	return pext->p_uint8(0);
}

static int ext_buffer_push_restriction_count(
	EXT_PUSH *pext, const RESTRICTION_COUNT *r)
{
	TRY(pext->p_uint32(r->count));
	return pext->p_restriction(&r->sub_res);
}

int EXT_PUSH::p_restriction(const RESTRICTION *r)
{
	auto pext = this;
	TRY(pext->p_uint8(r->rt));
	switch (r->rt) {
	case RES_AND:
	case RES_OR:
		return ext_buffer_push_restriction_and_or(pext, r->andor);
	case RES_NOT:
		return ext_buffer_push_restriction_not(pext, r->xnot);
	case RES_CONTENT:
		return ext_buffer_push_restriction_content(pext, r->cont);
	case RES_PROPERTY:
		return ext_buffer_push_restriction_property(pext, r->prop);
	case RES_PROPCOMPARE:
		return ext_buffer_push_restriction_propcompare(pext, r->pcmp);
	case RES_BITMASK:
		return ext_buffer_push_restriction_bitmask(pext, r->bm);
	case RES_SIZE:
		return ext_buffer_push_restriction_size(pext, r->size);
	case RES_EXIST:
		return ext_buffer_push_restriction_exist(pext, r->exist);
	case RES_SUBRESTRICTION:
		return ext_buffer_push_restriction_subobj(pext, r->sub);
	case RES_COMMENT:
		return ext_buffer_push_restriction_comment(pext, r->comment);
	case RES_COUNT:
		return ext_buffer_push_restriction_count(pext, r->count);
	case RES_NULL:
		return EXT_ERR_SUCCESS;
	}
	return EXT_ERR_BAD_SWITCH;
}

int EXT_PUSH::p_svreid(const SVREID *r)
{
	auto pext = this;
	if (NULL != r->pbin) {
		TRY(pext->p_uint16(r->pbin->cb + 1));
		TRY(pext->p_uint8(0));
		return pext->p_bytes(r->pbin->pb, r->pbin->cb);
	}
	TRY(pext->p_uint16(21));
	TRY(pext->p_uint8(1));
	TRY(pext->p_uint64(r->folder_id));
	TRY(pext->p_uint64(r->message_id));
	return pext->p_uint32(r->instance);
}

int EXT_PUSH::p_store_eid(const STORE_ENTRYID *r)
{
	auto pext = this;
	TRY(pext->p_uint32(r->flags));
	TRY(pext->p_bytes(r->provider_uid, 16));
	TRY(pext->p_uint8(r->version));
	TRY(pext->p_uint8(r->flag));
	TRY(pext->p_bytes(r->dll_name, 14));
	TRY(pext->p_uint32(r->wrapped_flags));
	TRY(pext->p_bytes(r->wrapped_provider_uid, 16));
	TRY(pext->p_uint32(r->wrapped_type));
	TRY(pext->p_str(r->pserver_name));
	return pext->p_str(r->pmailbox_dn);
}

static int ext_buffer_push_zmovecopy_action(EXT_PUSH *e,
    const ZMOVECOPY_ACTION *r)
{
	TRY(e->p_bin(&r->store_eid));
	return e->p_bin(&r->folder_eid);
}

static int ext_buffer_push_movecopy_action(EXT_PUSH *pext,
    const MOVECOPY_ACTION *r)
{
	auto &ext = *pext;
	uint16_t eid_size;
	
	TRY(pext->p_uint8(r->same_store));
	if (0 == r->same_store) {
		uint32_t offset = ext.m_offset;
		TRY(pext->advance(sizeof(uint16_t)));
		if (r->pstore_eid == nullptr)
			return EXT_ERR_FORMAT;
		TRY(pext->p_store_eid(r->pstore_eid));
		uint32_t offset1 = ext.m_offset;
		eid_size = offset1 - (offset + sizeof(uint16_t));
		ext.m_offset = offset;
		TRY(pext->p_uint16(eid_size));
		ext.m_offset = offset1;
	} else {
		TRY(pext->p_uint16(1));
		TRY(pext->p_uint8(0));
	}
	if (r->same_store != 0)
		return pext->p_svreid(static_cast<SVREID *>(r->pfolder_eid));
	else
		return pext->p_bin(static_cast<BINARY *>(r->pfolder_eid));
}

static int ext_buffer_push_zreply_action(EXT_PUSH *e, const ZREPLY_ACTION *r)
{
	TRY(e->p_bin(&r->message_eid));
	return e->p_guid(&r->template_guid);
}

static int ext_buffer_push_reply_action(
	EXT_PUSH *pext, const REPLY_ACTION *r)
{
	TRY(pext->p_uint64(r->template_folder_id));
	TRY(pext->p_uint64(r->template_message_id));
	return pext->p_guid(&r->template_guid);
}

static int ext_buffer_push_recipient_block(
	EXT_PUSH *pext, const RECIPIENT_BLOCK *r)
{
	if (r->count == 0)
		return EXT_ERR_FORMAT;
	TRY(pext->p_uint8(r->reserved));
	TRY(pext->p_uint16(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->p_tagged_pv(&r->ppropval[i]));
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_forwarddelegate_action(
	EXT_PUSH *pext, const FORWARDDELEGATE_ACTION *r)
{
	if (r->count == 0)
		return EXT_ERR_FORMAT;
	TRY(pext->p_uint16(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(ext_buffer_push_recipient_block(pext, &r->pblock[i]));
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_action_block(
	EXT_PUSH *pext, const ACTION_BLOCK *r)
{
	auto &ext = *pext;
	uint32_t offset = ext.m_offset;

	TRY(pext->advance(sizeof(uint16_t)));
	TRY(pext->p_uint8(r->type));
	TRY(pext->p_uint32(r->flavor));
	TRY(pext->p_uint32(r->flags));
	switch (r->type) {
	case OP_MOVE:
	case OP_COPY:
		TRY((pext->m_flags & EXT_FLAG_ZCORE) ?
		    ext_buffer_push_zmovecopy_action(pext, static_cast<ZMOVECOPY_ACTION *>(r->pdata)) :
		    ext_buffer_push_movecopy_action(pext, static_cast<MOVECOPY_ACTION *>(r->pdata)));
		break;
	case OP_REPLY:
	case OP_OOF_REPLY:
		TRY((pext->m_flags & EXT_FLAG_ZCORE) ?
		    ext_buffer_push_zreply_action(pext, static_cast<ZREPLY_ACTION *>(r->pdata)) :
		    ext_buffer_push_reply_action(pext, static_cast<REPLY_ACTION *>(r->pdata)));
		break;
	case OP_DEFER_ACTION: {
		uint16_t tmp_len = r->length - sizeof(uint8_t) - 2 * sizeof(uint32_t);
		TRY(pext->p_bytes(r->pdata, tmp_len));
		break;
	}
	case OP_BOUNCE:
		TRY(pext->p_uint32(*static_cast<uint32_t *>(r->pdata)));
		break;
	case OP_FORWARD:
	case OP_DELEGATE:
		TRY(ext_buffer_push_forwarddelegate_action(pext, static_cast<FORWARDDELEGATE_ACTION *>(r->pdata)));
		break;
	case OP_TAG:
		TRY(pext->p_tagged_pv(static_cast<TAGGED_PROPVAL *>(r->pdata)));
	case OP_DELETE:
	case OP_MARK_AS_READ:
		break;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
	uint16_t tmp_len = ext.m_offset - (offset + sizeof(uint16_t));
	uint32_t offset1 = ext.m_offset;
	ext.m_offset = offset;
	TRY(pext->p_uint16(tmp_len));
	ext.m_offset = offset1;
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_rule_actions(const RULE_ACTIONS *r)
{
	auto pext = this;
	
	if (r->count == 0)
		return EXT_ERR_FORMAT;
	TRY(pext->p_uint16(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(ext_buffer_push_action_block(pext, &r->pblock[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_propval(uint16_t type, const void *pval)
{
	auto pext = this;
	if (m_flags & EXT_FLAG_ABK && (type == PT_STRING8 ||
	    type == PT_UNICODE || type == PT_BINARY || (type & MV_FLAG))) {
		if (pval == nullptr)
			return p_uint8(0);
		TRY(p_uint8(0xFF));
	} else if ((type & MVI_FLAG) == MVI_FLAG) {
		/* convert multi-value instance into single value */
		type &= ~MVI_FLAG;
	}
	switch (type) {
	case PT_UNSPECIFIED:
		return pext->p_typed_pv(static_cast<const TYPED_PROPVAL *>(pval));
	case PT_SHORT:
		return pext->p_uint16(*static_cast<const uint16_t *>(pval));
	case PT_LONG:
	case PT_ERROR:
		return pext->p_uint32(*static_cast<const uint32_t *>(pval));
	case PT_FLOAT:
		return pext->p_float(*static_cast<const float *>(pval));
	case PT_DOUBLE:
	case PT_APPTIME:
		return pext->p_double(*static_cast<const double *>(pval));
	case PT_BOOLEAN:
		return pext->p_uint8(*static_cast<const uint8_t *>(pval));
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME:
		return pext->p_uint64(*static_cast<const uint64_t *>(pval));
	case PT_STRING8:
		return pext->p_str(static_cast<const char *>(pval));
	case PT_UNICODE:
		return pext->p_wstr(static_cast<const char *>(pval));
	case PT_CLSID:
		return pext->p_guid(static_cast<const GUID *>(pval));
	case PT_SVREID:
		return pext->p_svreid(static_cast<const SVREID *>(pval));
	case PT_SRESTRICTION:
		return pext->p_restriction(static_cast<const RESTRICTION *>(pval));
	case PT_ACTIONS:
		return pext->p_rule_actions(static_cast<const RULE_ACTIONS *>(pval));
	case PT_BINARY:
	case PT_OBJECT:
		return pext->p_bin(static_cast<const BINARY *>(pval));
	case PT_MV_SHORT:
		return pext->p_uint16_a(static_cast<const SHORT_ARRAY *>(pval));
	case PT_MV_LONG:
		return pext->p_uint32_a(static_cast<const LONG_ARRAY *>(pval));
	case PT_MV_I8:
		return pext->p_uint64_a(static_cast<const LONGLONG_ARRAY *>(pval));
	case PT_MV_STRING8:
		return pext->p_str_a(static_cast<const STRING_ARRAY *>(pval));
	case PT_MV_UNICODE:
		return pext->p_wstr_a(static_cast<const STRING_ARRAY *>(pval));
	case PT_MV_CLSID:
		return pext->p_guid_a(static_cast<const GUID_ARRAY *>(pval));
	case PT_MV_BINARY:
		return pext->p_bin_a(static_cast<const BINARY_ARRAY *>(pval));
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int EXT_PUSH::p_typed_pv(const TYPED_PROPVAL *r)
{
	auto pext = this;
	TRY(pext->p_uint16(r->type));
	return pext->p_propval(r->type, r->pvalue);
}

int EXT_PUSH::p_tagged_pv(const TAGGED_PROPVAL *r)
{
	auto pext = this;
	TRY(pext->p_uint32(r->proptag));
	return pext->p_propval(PROP_TYPE(r->proptag), r->pvalue);
}

int EXT_PUSH::p_longterm(const LONG_TERM_ID *r)
{
	auto pext = this;
	TRY(pext->p_guid(&r->guid));
	TRY(p_bytes(r->global_counter.ab, 6));
	return pext->p_uint16(r->padding);
}

int EXT_PUSH::p_longterm_a(const LONG_TERM_ID_ARRAY *r)
{
	auto pext = this;
	
	TRY(pext->p_uint16(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->p_longterm(&r->pids[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_proptag_a(const PROPTAG_ARRAY *r)
{
	auto pext = this;
	
	TRY(pext->p_uint16(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->p_uint32(r->pproptag[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_proptag_a(const LPROPTAG_ARRAY *r)
{
	TRY(p_uint32(r->cvalues));
	for (size_t i = 0; i < r->cvalues; ++i)
		TRY(p_uint32(r->pproptag[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_propname(const PROPERTY_NAME *r)
{
	auto pext = this;
	
	TRY(pext->p_uint8(r->kind));
	TRY(pext->p_guid(&r->guid));
	if (r->kind == MNID_ID) {
		TRY(pext->p_uint32(r->lid));
	} else if (r->kind == MNID_STRING) {
		uint32_t offset = m_offset;
		TRY(pext->advance(sizeof(uint8_t)));
		TRY(pext->p_wstr(r->pname));
		uint8_t name_size = m_offset - (offset + sizeof(uint8_t));
		uint32_t offset1 = m_offset;
		m_offset = offset;
		TRY(pext->p_uint8(name_size));
		m_offset = offset1;
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_propname_a(const PROPNAME_ARRAY *r)
{
	auto pext = this;
	
	TRY(pext->p_uint16(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->p_propname(&r->ppropname[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_propid_a(const PROPID_ARRAY *r)
{
	auto pext = this;
	
	TRY(pext->p_uint16(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->p_uint16(r->ppropid[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_tpropval_a(const TPROPVAL_ARRAY *r)
{
	auto pext = this;
	
	TRY(pext->p_uint16(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->p_tagged_pv(&r->ppropval[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_tpropval_a(const LTPROPVAL_ARRAY *r)
{
	TRY(p_uint32(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(p_tagged_pv(&r->propval[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_tarray_set(const TARRAY_SET *r)
{
	auto pext = this;
	TRY(pext->p_uint32(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->p_tpropval_a(r->pparray[i]));
	return EXT_ERR_SUCCESS;
}


static int ext_buffer_push_property_problem(EXT_PUSH *pext, const PROPERTY_PROBLEM *r)
{
	TRY(pext->p_uint16(r->index));
	TRY(pext->p_uint32(r->proptag));
	return pext->p_uint32(r->err);
}

int EXT_PUSH::p_problem_a(const PROBLEM_ARRAY *r)
{
	auto pext = this;
	
	TRY(pext->p_uint16(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(ext_buffer_push_property_problem(pext, r->pproblem + i));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_xid(const XID &xid)
{
	if (xid.size < 17 || xid.size > 24)
		return EXT_ERR_FORMAT;
	TRY(p_guid(&xid.guid));
	return p_bytes(xid.local_id, xid.size - 16);
}

int EXT_PUSH::p_folder_eid(const FOLDER_ENTRYID *r)
{
	auto pext = this;
	TRY(pext->p_uint32(r->flags));
	TRY(pext->p_bytes(r->provider_uid, 16));
	TRY(pext->p_uint16(r->folder_type));
	TRY(pext->p_guid(&r->database_guid));
	TRY(p_bytes(r->global_counter.ab, 6));
	return pext->p_bytes(r->pad, 2);
}

int EXT_PUSH::p_msg_eid(const MESSAGE_ENTRYID *r)
{
	auto pext = this;
	TRY(pext->p_uint32(r->flags));
	TRY(pext->p_bytes(r->provider_uid, 16));
	TRY(pext->p_uint16(r->message_type));
	TRY(pext->p_guid(&r->folder_database_guid));
	TRY(p_bytes(r->folder_global_counter.ab, 6));
	TRY(pext->p_bytes(r->pad1, 2));
	TRY(pext->p_guid(&r->message_database_guid));
	TRY(p_bytes(r->message_global_counter.ab, 6));
	return pext->p_bytes(r->pad2, 2);
}

int EXT_PUSH::p_flagged_pv(uint16_t type, const FLAGGED_PROPVAL *r)
{
	auto pext = this;
	void *pvalue = nullptr;
	
	if (type == PT_UNSPECIFIED && !(m_flags & EXT_FLAG_ABK)) {
		if (FLAGGED_PROPVAL_FLAG_UNAVAILABLE == r->flag) {
			type = 0;
		} else if (FLAGGED_PROPVAL_FLAG_ERROR == r->flag) {
			type = PT_ERROR;
			pvalue = r->pvalue;
		} else {
			type = ((TYPED_PROPVAL*)r->pvalue)->type;
			pvalue = ((TYPED_PROPVAL*)r->pvalue)->pvalue;
		}
		TRY(pext->p_uint16(type));
	} else {
		pvalue = r->pvalue;
	}
	TRY(pext->p_uint8(r->flag));
	switch (r->flag) {
	case FLAGGED_PROPVAL_FLAG_AVAILABLE:
		return pext->p_propval(type, pvalue);
	case FLAGGED_PROPVAL_FLAG_UNAVAILABLE:
		return EXT_ERR_SUCCESS;
	case FLAGGED_PROPVAL_FLAG_ERROR:
		return pext->p_uint32(*static_cast<uint32_t *>(pvalue));
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int EXT_PUSH::p_proprow(const PROPTAG_ARRAY *pcolumns, const PROPERTY_ROW *r)
{
	auto pext = this;
	
	TRY(pext->p_uint8(r->flag));
	if (PROPERTY_ROW_FLAG_NONE == r->flag) {
		for (size_t i = 0; i < pcolumns->count; ++i)
			TRY(pext->p_propval(PROP_TYPE(pcolumns->pproptag[i]), r->pppropval[i]));
		return EXT_ERR_SUCCESS;
	} else if (PROPERTY_ROW_FLAG_FLAGGED == r->flag) {
		for (size_t i = 0; i < pcolumns->count; ++i)
			TRY(pext->p_flagged_pv(PROP_TYPE(pcolumns->pproptag[i]),
			         static_cast<FLAGGED_PROPVAL *>(r->pppropval[i])));
		return EXT_ERR_SUCCESS;
	}
	return EXT_ERR_BAD_SWITCH;
}

int EXT_PUSH::p_proprow(const LPROPTAG_ARRAY *cols, const PROPERTY_ROW *r)
{
	TRY(p_uint8(r->flag));
	if (r->flag == PROPERTY_ROW_FLAG_NONE) {
		for (size_t i = 0; i < cols->cvalues; ++i)
			TRY(p_propval(PROP_TYPE(cols->pproptag[i]), r->pppropval[i]));
		return EXT_ERR_SUCCESS;
	} else if (r->flag == PROPERTY_ROW_FLAG_FLAGGED) {
		for (size_t i = 0; i < cols->cvalues; ++i)
			TRY(p_flagged_pv(PROP_TYPE(cols->pproptag[i]),
			         static_cast<FLAGGED_PROPVAL *>(r->pppropval[i])));
		return EXT_ERR_SUCCESS;
	}
	return EXT_ERR_BAD_SWITCH;
}

int EXT_PUSH::p_sortorder(const SORT_ORDER *r)
{
	auto pext = this;
	if ((r->type & MVI_FLAG) == MV_FLAG)
		/* MV_FLAG set without MV_INSTANCE */
		return EXT_ERR_FORMAT;
	TRY(pext->p_uint16(r->type));
	TRY(pext->p_uint16(r->propid));
	return pext->p_uint8(r->table_sort);
}

int EXT_PUSH::p_sortorder_set(const SORTORDER_SET *r)
{
	auto pext = this;
	
	if (r->count == 0 || r->ccategories > r->count || r->cexpanded > r->ccategories)
		return EXT_ERR_FORMAT;
	TRY(pext->p_uint16(r->count));
	TRY(pext->p_uint16(r->ccategories));
	TRY(pext->p_uint16(r->cexpanded));
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->p_sortorder(&r->psort[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_typed_str(const TYPED_STRING *r)
{
	auto pext = this;
	TRY(pext->p_uint8(r->string_type));
	switch(r->string_type) {
	case STRING_TYPE_NONE:
	case STRING_TYPE_EMPTY:
		return EXT_ERR_SUCCESS;
	case STRING_TYPE_STRING8:
	case STRING_TYPE_UNICODE_REDUCED:
		return pext->p_str(r->pstring);
	case STRING_TYPE_UNICODE:
		return pext->p_wstr(r->pstring);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int EXT_PUSH::p_recipient_row(const PROPTAG_ARRAY *pproptags, const RECIPIENT_ROW *r)
{
	auto pext = this;
	BOOL b_unicode;
	PROPTAG_ARRAY proptags;
	
	b_unicode = FALSE;
	if (r->flags & RECIPIENT_ROW_FLAG_UNICODE)
		b_unicode = TRUE;
	TRY(pext->p_uint16(r->flags));
	if (r->pprefix_used != nullptr)
		TRY(pext->p_uint8(*r->pprefix_used));
	if (r->have_display_type)
		TRY(pext->p_uint8(r->display_type));
	if (r->px500dn != nullptr)
		TRY(pext->p_str(r->px500dn));
	if (r->pentry_id != nullptr)
		TRY(pext->p_bin(r->pentry_id));
	if (r->psearch_key != nullptr)
		TRY(pext->p_bin(r->psearch_key));
	if (r->paddress_type != nullptr)
		TRY(pext->p_str(r->paddress_type));
	if (NULL != r->pmail_address) {
		if (b_unicode)
			TRY(pext->p_wstr(r->pmail_address));
		else
			TRY(pext->p_str(r->pmail_address));
	}
	if (NULL != r->pdisplay_name) {
		if (b_unicode)
			TRY(pext->p_wstr(r->pdisplay_name));
		else
			TRY(pext->p_str(r->pdisplay_name));
	}
	if (NULL != r->psimple_name) {
		if (b_unicode)
			TRY(pext->p_wstr(r->psimple_name));
		else
			TRY(pext->p_str(r->psimple_name));
	}
	if (NULL != r->ptransmittable_name) {
		if (b_unicode)
			TRY(pext->p_wstr(r->ptransmittable_name));
		else
			TRY(pext->p_str(r->ptransmittable_name));
	}
	TRY(pext->p_uint16(r->count));
	if (r->count > pproptags->count)
		return EXT_ERR_FORMAT;
	proptags.count = r->count;
	proptags.pproptag = (uint32_t*)pproptags->pproptag;
	return pext->p_proprow(&proptags, &r->properties);
}

int EXT_PUSH::p_openrecipient_row(const PROPTAG_ARRAY *pproptags, const OPENRECIPIENT_ROW *r)
{
	auto pext = this;
	
	TRY(pext->p_uint8(r->recipient_type));
	TRY(pext->p_uint16(r->cpid));
	TRY(pext->p_uint16(r->reserved));
	uint32_t offset = m_offset;
	TRY(pext->advance(sizeof(uint16_t)));
	TRY(pext->p_recipient_row(pproptags, &r->recipient_row));
	uint16_t row_size = m_offset - (offset + sizeof(uint16_t));
	uint32_t offset1 = m_offset;
	m_offset = offset;
	TRY(pext->p_uint16(row_size));
	m_offset = offset1;
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_readrecipient_row(const PROPTAG_ARRAY *pproptags, const READRECIPIENT_ROW *r)
{
	auto pext = this;
	
	TRY(pext->p_uint32(r->row_id));
	TRY(pext->p_uint8(r->recipient_type));
	TRY(pext->p_uint16(r->cpid));
	TRY(pext->p_uint16(r->reserved));
	uint32_t offset = m_offset;
	TRY(pext->advance(sizeof(uint16_t)));
	TRY(pext->p_recipient_row(pproptags, &r->recipient_row));
	uint16_t row_size = m_offset - (offset + sizeof(uint16_t));
	uint32_t offset1 = m_offset;
	m_offset = offset;
	TRY(pext->p_uint16(row_size));
	m_offset = offset1;
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_permission_data(const PERMISSION_DATA *r)
{
	auto pext = this;
	TRY(pext->p_uint8(r->flags));
	return pext->p_tpropval_a(&r->propvals);
}

int EXT_PUSH::p_rule_data(const RULE_DATA *r)
{
	auto pext = this;
	TRY(pext->p_uint8(r->flags));
	return pext->p_tpropval_a(&r->propvals);
}

int EXT_PUSH::p_abk_eid(const ADDRESSBOOK_ENTRYID *r)
{
	auto pext = this;
	TRY(pext->p_uint32(r->flags));
	TRY(pext->p_bytes(r->provider_uid, 16));
	TRY(pext->p_uint32(r->version));
	TRY(pext->p_uint32(r->type));
	return pext->p_str(r->px500dn);
}

int EXT_PUSH::p_oneoff_eid(const ONEOFF_ENTRYID *r)
{
	auto pext = this;
	TRY(pext->p_uint32(r->flags));
	TRY(pext->p_bytes(r->provider_uid, 16));
	TRY(pext->p_uint16(r->version));
	TRY(pext->p_uint16(r->ctrl_flags));
	if (r->ctrl_flags & CTRL_FLAG_UNICODE) {
		TRY(pext->p_wstr(r->pdisplay_name));
		TRY(pext->p_wstr(r->paddress_type));
		return pext->p_wstr(r->pmail_address);
	} else {
		TRY(pext->p_str(r->pdisplay_name));
		TRY(pext->p_str(r->paddress_type));
		return pext->p_str(r->pmail_address);
	}
}

static int ext_buffer_push_persistelement(
	EXT_PUSH *pext, const PERSISTELEMENT *r)
{
	TRY(pext->p_uint16(r->element_id));
	switch (r->element_id) {
	case RSF_ELID_HEADER:
		TRY(pext->p_uint16(4));
		return pext->p_uint32(0);
	case RSF_ELID_ENTRYID:
		return pext->p_bin(r->pentry_id);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

static int ext_buffer_push_persistdata(EXT_PUSH *pext, const PERSISTDATA *r)
{
	auto &ext = *pext;
	TRY(pext->p_uint16(r->persist_id));
	if (r->persist_id == PERSIST_SENTINEL)
		return pext->p_uint16(0);
	uint32_t offset = ext.m_offset;
	TRY(pext->advance(sizeof(uint16_t)));
	TRY(ext_buffer_push_persistelement(pext, &r->element));
	uint16_t tmp_size = ext.m_offset - (offset + sizeof(uint16_t));
	uint32_t offset1 = ext.m_offset;
	ext.m_offset = offset;
	TRY(pext->p_uint16(tmp_size));
	ext.m_offset = offset1;
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_persistdata_a(const PERSISTDATA_ARRAY *r)
{
	auto pext = this;
	PERSISTDATA last_data;
	
	for (size_t i = 0; i < r->count; ++i)
		TRY(ext_buffer_push_persistdata(pext, r->ppitems[i]));
	last_data.persist_id = PERSIST_SENTINEL;
	last_data.element.element_id = ELEMENT_SENTINEL;
	last_data.element.pentry_id = NULL;
	return ext_buffer_push_persistdata(pext, &last_data);
}

int EXT_PUSH::p_eid_a(const EID_ARRAY *r)
{
	auto pext = this;
	TRY(pext->p_uint32(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->p_uint64(r->pids[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_systime(const SYSTEMTIME *r)
{
	auto pext = this;
	TRY(pext->p_int16(r->year));
	TRY(pext->p_int16(r->month));
	TRY(pext->p_int16(r->dayofweek));
	TRY(pext->p_int16(r->day));
	TRY(pext->p_int16(r->hour));
	TRY(pext->p_int16(r->minute));
	TRY(pext->p_int16(r->second));
	return pext->p_int16(r->milliseconds);
}

int EXT_PUSH::p_tzstruct(const TIMEZONESTRUCT *r)
{
	auto pext = this;
	TRY(pext->p_int32(r->bias));
	TRY(pext->p_int32(r->standardbias));
	TRY(pext->p_int32(r->daylightbias));
	TRY(pext->p_int16(r->standardyear));
	TRY(pext->p_systime(&r->standarddate));
	TRY(pext->p_int16(r->daylightyear));
	return pext->p_systime(&r->daylightdate);
}

static int ext_buffer_push_tzrule(EXT_PUSH *pext, const TZRULE *r)
{
	TRY(pext->p_uint8(r->major));
	TRY(pext->p_uint8(r->minor));
	TRY(pext->p_uint16(r->reserved));
	TRY(pext->p_uint16(r->flags));
	TRY(pext->p_int16(r->year));
	TRY(pext->p_bytes(r->x, 14));
	TRY(pext->p_int32(r->bias));
	TRY(pext->p_int32(r->standardbias));
	TRY(pext->p_int32(r->daylightbias));
	TRY(pext->p_systime(&r->standarddate));
	return pext->p_systime(&r->daylightdate);
}

int EXT_PUSH::p_tzdef(const TIMEZONEDEFINITION *r)
{
	auto pext = this;
	int len;
	uint16_t cbheader;
	char tmp_buff[262];
	
	TRY(pext->p_uint8(r->major));
	TRY(pext->p_uint8(r->minor));
	len = utf8_to_utf16le(r->keyname, tmp_buff, 262);
	if (len < 2)
		return EXT_ERR_CHARCNV;
	len -= 2;
	cbheader = 6 + len;
	TRY(pext->p_uint16(cbheader));
	TRY(pext->p_uint16(r->reserved));
	TRY(pext->p_uint16(len / 2));
	TRY(pext->p_bytes(tmp_buff, len));
	TRY(pext->p_uint16(r->crules));
	for (size_t i = 0; i < r->crules; ++i)
		TRY(ext_buffer_push_tzrule(pext, r->prules + i));
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_patterntypespecific(EXT_PUSH *pext,
    uint16_t patterntype, const PATTERNTYPE_SPECIFIC *r)
{
	switch (patterntype) {
	case PATTERNTYPE_DAY:
		/* do nothing */
		return EXT_ERR_SUCCESS;
	case PATTERNTYPE_WEEK:
		return pext->p_uint32(r->weekrecur);
	case PATTERNTYPE_MONTH:
	case PATTERNTYPE_MONTHEND:
	case PATTERNTYPE_HJMONTH:
	case PATTERNTYPE_HJMONTHEND:
		return pext->p_uint32(r->dayofmonth);
	case PATTERNTYPE_MONTHNTH:
	case PATTERNTYPE_HJMONTHNTH:
		TRY(pext->p_uint32(r->monthnth.weekrecur));
		return pext->p_uint32(r->monthnth.recurnum);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

static int ext_buffer_push_recurrencepattern(EXT_PUSH *pext, const RECURRENCE_PATTERN *r)
{
	TRY(pext->p_uint16(r->readerversion));
	TRY(pext->p_uint16(r->writerversion));
	TRY(pext->p_uint16(r->recurfrequency));
	TRY(pext->p_uint16(r->patterntype));
	TRY(pext->p_uint16(r->calendartype));
	TRY(pext->p_uint32(r->firstdatetime));
	TRY(pext->p_uint32(r->period));
	TRY(pext->p_uint32(r->slidingflag));
	TRY(ext_buffer_push_patterntypespecific(pext, r->patterntype, &r->pts));
	TRY(pext->p_uint32(r->endtype));
	TRY(pext->p_uint32(r->occurrencecount));
	TRY(pext->p_uint32(r->firstdow));
	TRY(pext->p_uint32(r->deletedinstancecount));
	for (size_t i = 0; i < r->deletedinstancecount; ++i)
		TRY(pext->p_uint32(r->pdeletedinstancedates[i]));
	TRY(pext->p_uint32(r->modifiedinstancecount));
	for (size_t i = 0; i < r->modifiedinstancecount; ++i)
		TRY(pext->p_uint32(r->pmodifiedinstancedates[i]));
	TRY(pext->p_uint32(r->startdate));
	return pext->p_uint32(r->enddate);
}

static int ext_buffer_push_exceptioninfo(
	EXT_PUSH *pext, const EXCEPTIONINFO *r)
{
	uint16_t tmp_len;
	
	TRY(pext->p_uint32(r->startdatetime));
	TRY(pext->p_uint32(r->enddatetime));
	TRY(pext->p_uint32(r->originalstartdate));
	TRY(pext->p_uint16(r->overrideflags));
	if (r->overrideflags & OVERRIDEFLAG_SUBJECT) {
		tmp_len = strlen(r->subject);
		TRY(pext->p_uint16(tmp_len + 1));
		TRY(pext->p_uint16(tmp_len));
		TRY(pext->p_bytes(r->subject, tmp_len));
	}
	if (r->overrideflags & OVERRIDEFLAG_MEETINGTYPE)
		TRY(pext->p_uint32(r->meetingtype));
	if (r->overrideflags & OVERRIDEFLAG_REMINDERDELTA)
		TRY(pext->p_uint32(r->reminderdelta));
	if (r->overrideflags & OVERRIDEFLAG_REMINDER)
		TRY(pext->p_uint32(r->reminderset));
	if (r->overrideflags & OVERRIDEFLAG_LOCATION) {
		tmp_len = strlen(r->location);
		TRY(pext->p_uint16(tmp_len + 1));
		TRY(pext->p_uint16(tmp_len));
		TRY(pext->p_bytes(r->location, tmp_len));
	}
	if (r->overrideflags & OVERRIDEFLAG_BUSYSTATUS)
		TRY(pext->p_uint32(r->busystatus));
	if (r->overrideflags & OVERRIDEFLAG_ATTACHMENT)
		TRY(pext->p_uint32(r->attachment));
	if (r->overrideflags & OVERRIDEFLAG_SUBTYPE)
		TRY(pext->p_uint32(r->subtype));
	if (r->overrideflags & OVERRIDEFLAG_APPTCOLOR)
		TRY(pext->p_uint32(r->appointmentcolor));
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_changehighlight(
	EXT_PUSH *pext, const CHANGEHIGHLIGHT *r)
{
	TRY(pext->p_uint32(r->size));
	TRY(pext->p_uint32(r->value));
	if (r->size < sizeof(uint32_t))
		return EXT_ERR_FORMAT;
	else if (sizeof(uint32_t) == r->size)
		return EXT_ERR_SUCCESS;
	return pext->p_bytes(r->preserved, r->size - sizeof(uint32_t));
}

static int ext_buffer_push_extendedexception(
	EXT_PUSH *pext, uint32_t writerversion2,
	uint16_t overrideflags, const EXTENDEDEXCEPTION *r)
{
	int string_len;
	uint16_t tmp_len;
	
	if (writerversion2 >= 0x00003009)
		TRY(ext_buffer_push_changehighlight(pext, &r->changehighlight));
	TRY(pext->p_uint32(r->reservedblockee1size));
	if (r->reservedblockee1size != 0)
		TRY(pext->p_bytes(r->preservedblockee1, r->reservedblockee1size));
	if ((overrideflags & OVERRIDEFLAG_LOCATION) ||
		(overrideflags & OVERRIDEFLAG_SUBJECT)) {
		TRY(pext->p_uint32(r->startdatetime));
		TRY(pext->p_uint32(r->enddatetime));
		TRY(pext->p_uint32(r->originalstartdate));
	}
	if (overrideflags & OVERRIDEFLAG_SUBJECT) {
		tmp_len = strlen(r->subject) + 1;
		std::unique_ptr<char[]> pbuff;
		try {
			pbuff = std::make_unique<char[]>(2 * tmp_len);
		} catch (const std::bad_alloc &) {
			return EXT_ERR_ALLOC;
		}
		string_len = utf8_to_utf16le(r->subject, pbuff.get(), 2 * tmp_len);
		if (string_len < 2)
			return EXT_ERR_CHARCNV;
		string_len -= 2;
		TRY(pext->p_uint16(string_len / 2));
		TRY(pext->p_bytes(pbuff.get(), string_len));
	}
	if (overrideflags & OVERRIDEFLAG_LOCATION) {
		tmp_len = strlen(r->location) + 1;
		std::unique_ptr<char[]> pbuff;
		try {
			pbuff = std::make_unique<char[]>(2 * tmp_len);
		} catch (const std::bad_alloc &) {
			return EXT_ERR_ALLOC;
		}
		string_len = utf8_to_utf16le(r->location, pbuff.get(), 2 * tmp_len);
		if (string_len < 2)
			return EXT_ERR_CHARCNV;
		string_len -= 2;
		TRY(pext->p_uint16(string_len / 2));
		TRY(pext->p_bytes(pbuff.get(), string_len));
	}
	if ((overrideflags & OVERRIDEFLAG_LOCATION) ||
		(overrideflags & OVERRIDEFLAG_SUBJECT)) {
		TRY(pext->p_uint32(r->reservedblockee2size));
		if (r->reservedblockee2size != 0)
			TRY(pext->p_bytes(r->preservedblockee2, r->reservedblockee2size));
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_apptrecpat(const APPOINTMENT_RECUR_PAT *r)
{
	auto pext = this;
	
	TRY(ext_buffer_push_recurrencepattern(pext, &r->recur_pat));
	TRY(pext->p_uint32(r->readerversion2));
	TRY(pext->p_uint32(r->writerversion2));
	TRY(pext->p_uint32(r->starttimeoffset));
	TRY(pext->p_uint32(r->endtimeoffset));
	TRY(pext->p_uint16(r->exceptioncount));
	for (size_t i = 0; i < r->exceptioncount; ++i)
		TRY(ext_buffer_push_exceptioninfo(pext, &r->pexceptioninfo[i]));
	TRY(pext->p_uint32(r->reservedblock1size));
	for (size_t i = 0; i < r->exceptioncount; ++i)
		TRY(ext_buffer_push_extendedexception(pext, r->writerversion2, r->pexceptioninfo[i].overrideflags, &r->pextendedexception[i]));
	TRY(pext->p_uint32(r->reservedblock2size));
	if (r->reservedblock2size == 0)
		return EXT_ERR_SUCCESS;
	return pext->p_bytes(r->preservedblock2, r->reservedblock2size);
}

int EXT_PUSH::p_goid(const GLOBALOBJECTID *r)
{
	auto pext = this;
	TRY(pext->p_bytes(r->arrayid, 16));
	TRY(pext->p_uint8(r->year >> 8));
	TRY(pext->p_uint8(r->year & 0xFF));
	TRY(pext->p_uint8(r->month));
	TRY(pext->p_uint8(r->day));
	TRY(pext->p_uint64(r->creationtime));
	TRY(pext->p_bytes(r->x, 8));
	return pext->p_bin_ex(&r->data);
}


static int ext_buffer_push_attachment_list(
	EXT_PUSH *pext, const ATTACHMENT_LIST *r)
{
	int i;
	
	TRY(pext->p_uint16(r->count));
	for (i=0; i<r->count; i++) {
		TRY(pext->p_tpropval_a(&r->pplist[i]->proplist));
		if (NULL != r->pplist[i]->pembedded) {
			TRY(pext->p_uint8(1));
			TRY(pext->p_msgctnt(r->pplist[i]->pembedded));
		} else {
			TRY(pext->p_uint8(0));
		}
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_msgctnt(const MESSAGE_CONTENT *r)
{
	auto pext = this;
	TRY(pext->p_tpropval_a(&r->proplist));
	if (NULL != r->children.prcpts) {
		TRY(pext->p_uint8(1));
		TRY(pext->p_tarray_set(r->children.prcpts));
	} else {
		TRY(pext->p_uint8(0));
	}
	if (NULL != r->children.pattachments) {
		TRY(pext->p_uint8(1));
		return ext_buffer_push_attachment_list(
				pext, r->children.pattachments);
	} else {
		return pext->p_uint8(0);
	}
}

uint8_t *EXT_PUSH::release()
{
	auto p = this;
	auto t = p->m_udata;
	m_udata = nullptr;
	p->b_alloc = false;
	m_offset = 0;
	return t;
}
