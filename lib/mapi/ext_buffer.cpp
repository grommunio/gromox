// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/endian.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/util.hpp>
#define TRY(expr) do { int klfdv = (expr); if (klfdv != EXT_ERR_SUCCESS) return klfdv; } while (false)

using namespace gromox;

/*
 * On the matter of %EXT_FLAG_ABK: When NSP is run over MH, some nonsensical
 * alternate data formats are used. OXCMAPIHTTP v13 §2.2.1 mentions some of
 * these. The document is grossly incomplete. Only §2.2.1.1 specifies a
 * HasValue field, but 0xFF bytes can appear in other structs too.
 */

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
	TRY(g_uint16(&r->version));
	TRY(g_uint16(&r->flags));
	TRY(g_uint16(&r->size));
	return g_uint16(&r->size_actual);
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
	static_assert(std::numeric_limits<float>::is_iec559);
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_double(double *v)
{
	if (m_data_size < sizeof(double) ||
	    m_offset + sizeof(double) > m_data_size)
		return EXT_ERR_BUFSIZE;
	memcpy(v, &m_udata[m_offset], sizeof(*v));
	m_offset += sizeof(double);
	static_assert(std::numeric_limits<double>::is_iec559);
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
	TRY(g_uint32(&r->time_low));
	TRY(g_uint16(&r->time_mid));
	TRY(g_uint16(&r->time_hi_and_version));
	TRY(g_bytes(r->clock_seq, 2));
	TRY(g_bytes(r->node, 6));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_str(char **ppstr)
{
	if (m_offset >= m_data_size)
		return EXT_ERR_BUFSIZE;
	auto len = strnlen(&m_cdata[m_offset], m_data_size - m_offset);
	if (len + 1 > m_data_size - m_offset)
		return EXT_ERR_BUFSIZE;
	len ++;
	*ppstr = anew<char>(len);
	if (*ppstr == nullptr)
		return EXT_ERR_ALLOC;
	memcpy(*ppstr, &m_udata[m_offset], len);
	return advance(len);
}

int EXT_PULL::g_wstr(char **ppstr)
{
	/* Everything is measured in octects */
	size_t i;
	
	if (!(m_flags & EXT_FLAG_UTF16))
		return g_str(ppstr);
	if (m_offset >= m_data_size)
		return EXT_ERR_BUFSIZE;
	size_t max_len = m_data_size - m_offset;
	for (i = 0; i < max_len - 1; i += 2)
		if (m_udata[m_offset+i] == '\0' && m_udata[m_offset+i+1] == '\0')
			break;
	if (i >= max_len - 1)
		return EXT_ERR_BUFSIZE;
	auto len = i + 2;
	auto bufsize = utf16_to_utf8_len(len);
	*ppstr = anew<char>(bufsize);
	if (*ppstr == nullptr)
		return EXT_ERR_ALLOC;
	if (!utf16le_to_utf8(&m_cdata[m_offset], len, *ppstr, bufsize))
		return EXT_ERR_CHARCNV;
	return advance(len);
}

int EXT_PULL::g_blob(DATA_BLOB *pblob)
{
	
	if (m_offset > m_data_size)
		return EXT_ERR_BUFSIZE;
	uint32_t length = m_data_size - m_offset;
	pblob->data = anew<uint8_t>(length);
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
	
	if (m_flags & EXT_FLAG_WCOUNT) {
		TRY(g_uint32(&r->cb));
	} else {
		TRY(g_uint16(&cb));
		r->cb = cb;
	}
	if (r->cb == 0) {
		r->pb = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pv = m_alloc(r->cb);
	if (r->pv == nullptr) {
		r->cb = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(r->pv, r->cb);
}

int EXT_PULL::g_sbin(BINARY *r)
{
	uint16_t cb;
	
	TRY(g_uint16(&cb));
	r->cb = cb;
	if (r->cb == 0) {
		r->pb = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pv = m_alloc(r->cb);
	if (r->pv == nullptr) {
		r->cb = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(r->pv, r->cb);
}

int EXT_PULL::g_exbin(BINARY *r)
{
	TRY(g_uint32(&r->cb));
	if (r->cb == 0) {
		r->pb = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pv = m_alloc(r->cb);
	if (r->pv == nullptr) {
		r->cb = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(r->pv, r->cb);
}

int EXT_PULL::g_uint16_a(SHORT_ARRAY *r)
{
	TRY(g_uint32(&r->count));
	if (r->count == 0) {
		r->ps = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ps = anew<uint16_t>(r->count);
	if (r->ps == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(g_uint16(&r->ps[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_uint32_a(LONG_ARRAY *r)
{
	TRY(g_uint32(&r->count));
	if (r->count == 0) {
		r->pl = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pl = anew<uint32_t>(r->count);
	if (r->pl == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(g_uint32(&r->pl[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_uint64_a(LONGLONG_ARRAY *r)
{
	TRY(g_uint32(&r->count));
	if (r->count == 0) {
		r->pll = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pll = anew<uint64_t>(r->count);
	if (r->pll == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(g_uint64(&r->pll[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_uint64_sa(LONGLONG_ARRAY *r)
{
	uint16_t count;
	
	TRY(g_uint16(&count));
	r->count = count;
	if (r->count == 0) {
		r->pll = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pll = anew<uint64_t>(r->count);
	if (r->pll == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(g_uint64(&r->pll[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_float_a(FLOAT_ARRAY *r)
{
	TRY(g_uint32(&r->count));
	if (r->count == 0) {
		r->mval = nullptr;
		return EXT_ERR_SUCCESS;
	}
	r->mval = anew<float>(r->count);
	if (r->mval == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(g_float(&r->mval[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_double_a(DOUBLE_ARRAY *r)
{
	TRY(g_uint32(&r->count));
	if (r->count == 0) {
		r->mval = nullptr;
		return EXT_ERR_SUCCESS;
	}
	r->mval = anew<double>(r->count);
	if (r->mval == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(g_double(&r->mval[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_bin_a(BINARY_ARRAY *r)
{
	TRY(g_uint32(&r->count));
	if (r->count == 0) {
		r->pbin = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pbin = anew<BINARY>(r->count);
	if (r->pbin == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i) {
		if (m_flags & EXT_FLAG_ABK) {
			uint8_t value_set;
			TRY(g_uint8(&value_set));
			if (value_set == 0) {
				r->pbin[i].cb = 0;
				r->pbin[i].pb = nullptr;
				continue;
			} else if (value_set != 0xFF) {
				return EXT_ERR_FORMAT;
			}
		}
		TRY(g_bin(&r->pbin[i]));
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_str_a(STRING_ARRAY *r)
{
	TRY(g_uint32(&r->count));
	if (r->count == 0) {
		r->ppstr = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppstr = anew<char *>(r->count);
	if (r->ppstr == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i) {
		if (m_flags & EXT_FLAG_ABK) {
			uint8_t value_set;
			TRY(g_uint8(&value_set));
			if (value_set == 0) {
				r->ppstr[i] = nullptr;
				continue;
			} else if (value_set != 0xFF) {
				return EXT_ERR_FORMAT;
			}
		}
		TRY(g_str(&r->ppstr[i]));
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_wstr_a(STRING_ARRAY *r)
{
	TRY(g_uint32(&r->count));
	if (r->count == 0) {
		r->ppstr = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppstr = anew<char *>(r->count);
	if (r->ppstr == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i) {
		if (m_flags & EXT_FLAG_ABK) {
			uint8_t value_set;
			TRY(g_uint8(&value_set));
			if (value_set == 0) {
				r->ppstr[i] = nullptr;
				continue;
			} else if (value_set != 0xFF) {
				return EXT_ERR_FORMAT;
			}
		}
		TRY(g_wstr(&r->ppstr[i]));
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_guid_a(GUID_ARRAY *r)
{
	TRY(g_uint32(&r->count));
	if (r->count == 0) {
		r->pguid = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pguid = anew<GUID>(r->count);
	if (r->pguid == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(g_guid(&r->pguid[i]));
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
	if (r->count == 0) {
		r->pres = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pres = pext->anew<RESTRICTION>(r->count);
	if (r->pres == nullptr) {
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
	if (pext->m_flags & EXT_FLAG_ABK) {
		/* modeled upon restriction_property; presumed to occur */
		uint8_t value_set;
		TRY(pext->g_uint8(&value_set));
		if (value_set == 0) {
			r->propval = {};
			return EXT_ERR_SUCCESS;
		} else if (value_set != 0xFF) {
			return EXT_ERR_FORMAT;
		}
	}
	return pext->g_tagged_pv(&r->propval);
}

static int ext_buffer_pull_restriction_property(
	EXT_PULL *pext, RESTRICTION_PROPERTY *r)
{
	uint8_t relop;
	
	TRY(pext->g_uint8(&relop));
	r->relop = static_cast<enum relop>(relop);
	TRY(pext->g_uint32(&r->proptag));
	if (pext->m_flags & EXT_FLAG_ABK) {
		uint8_t value_set;
		TRY(pext->g_uint8(&value_set));
		if (value_set == 0) {
			r->propval = {};
			return EXT_ERR_SUCCESS;
		} else if (value_set != 0xFF) {
			return EXT_ERR_FORMAT;
		}
	}
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
	if (r->ppropval == nullptr) {
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
	
	TRY(g_uint8(&rt));
	r->rt = static_cast<res_type>(rt);
	switch (r->rt) {
	case RES_AND:
	case RES_OR:
		r->pres = anew<RESTRICTION_AND_OR>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_and_or(this, r->andor);
	case RES_NOT:
		r->pres = anew<RESTRICTION_NOT>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_not(this, r->xnot);
	case RES_CONTENT:
		r->pres = anew<RESTRICTION_CONTENT>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_content(this, r->cont);
	case RES_PROPERTY:
		r->pres = anew<RESTRICTION_PROPERTY>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_property(this, r->prop);
	case RES_PROPCOMPARE:
		r->pres = anew<RESTRICTION_PROPCOMPARE>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_propcompare(this, r->pcmp);
	case RES_BITMASK:
		r->pres = anew<RESTRICTION_BITMASK>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_bitmask(this, r->bm);
	case RES_SIZE:
		r->pres = anew<RESTRICTION_SIZE>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_size(this, r->size);
	case RES_EXIST:
		r->pres = anew<RESTRICTION_EXIST>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_exist(this, r->exist);
	case RES_SUBRESTRICTION:
		r->pres = anew<RESTRICTION_SUBOBJ>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_subobj(this, r->sub);
	case RES_COMMENT:
	case RES_ANNOTATION:
		r->pres = anew<RESTRICTION_COMMENT>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_comment(this, r->comment);
	case RES_COUNT:
		r->pres = anew<RESTRICTION_COUNT>();
		if (r->pres == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_restriction_count(this, r->count);
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
	
	TRY(g_uint16(&length));
	TRY(g_uint8(&ours));
	if (!ours) {
		r->folder_id = 0;
		r->message_id = 0;
		r->instance = 0;
		r->pbin = anew<BINARY>();
		if (r->pbin == nullptr)
			return EXT_ERR_ALLOC;
		r->pbin->cb = length > 0 ? length - 1 : 0;
		r->pbin->pv = m_alloc(r->pbin->cb);
		if (r->pbin->pv == nullptr) {
			r->pbin->cb = 0;
			return EXT_ERR_ALLOC;
		}
		return g_bytes(r->pbin->pv, r->pbin->cb);
	}
	if (length != 21)
		return EXT_ERR_FORMAT;
	r->pbin = NULL;
	TRY(g_uint64(&r->folder_id));
	TRY(g_uint64(&r->message_id));
	return g_uint32(&r->instance);
}

int EXT_PULL::g_store_eid(STORE_ENTRYID *r)
{
	FLATUID g;
	TRY(g_uint32(&r->flags));
	TRY(g_guid(&g));
	if (g != muidStoreWrap) {
		fprintf(stderr, "I-1969: not a wrapuid\n");
		return EXT_ERR_FORMAT;
	}
	TRY(g_uint8(&r->version));
	TRY(g_uint8(&r->flag));
	char dll[14];
	TRY(g_bytes(dll, 14));
	TRY(g_uint32(&r->wrapped_flags));
	TRY(g_guid(&r->wrapped_provider_uid));
	TRY(g_uint32(&r->wrapped_type));
	TRY(g_str(&r->pserver_name));
	return g_str(&r->pmailbox_dn);
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
	if (!r->same_store) {
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
	if (r->ppropval == nullptr) {
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
	if (r->pblock == nullptr) {
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
	TRY(g_uint16(&r->count));
	if (r->count == 0)
		return EXT_ERR_FORMAT;
	r->pblock = anew<ACTION_BLOCK>(r->count);
	if (r->pblock == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(ext_buffer_pull_action_block(this, &r->pblock[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_propval(uint16_t type, void **ppval)
{
	if (m_flags & EXT_FLAG_ABK && (type == PT_STRING8 || type == PT_UNICODE ||
	    type == PT_BINARY || (type & MV_FLAG))) {
		uint8_t value_set;
		TRY(g_uint8(&value_set));
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
#define CASE(mt, ct, fu) \
	case (mt): \
		*ppval = anew<ct>(); \
		if (*ppval == nullptr) \
			return EXT_ERR_ALLOC; \
		return fu(static_cast<ct *>(*ppval));

	switch (type) {
	CASE(PT_UNSPECIFIED, TYPED_PROPVAL, g_typed_pv);
	CASE(PT_SHORT, uint16_t, g_uint16);
	case PT_ERROR:
	CASE(PT_LONG, uint32_t, g_uint32);
	CASE(PT_FLOAT, float, g_float);
	case PT_APPTIME:
	CASE(PT_DOUBLE, double, g_double);
	CASE(PT_BOOLEAN, uint8_t, g_uint8);
	case PT_CURRENCY:
	case PT_SYSTIME:
	CASE(PT_I8, uint64_t, g_uint64);
	case PT_STRING8:
		return g_str(reinterpret_cast<char **>(ppval));
	case PT_UNICODE:
		return g_wstr(reinterpret_cast<char **>(ppval));
	CASE(PT_SVREID, SVREID, g_svreid);
	CASE(PT_CLSID, GUID, g_guid);
	CASE(PT_SRESTRICTION, RESTRICTION, g_restriction);
	CASE(PT_ACTIONS, RULE_ACTIONS, g_rule_actions);
	case PT_OBJECT:
	CASE(PT_BINARY, BINARY, g_bin);
	CASE(PT_MV_SHORT, SHORT_ARRAY, g_uint16_a);
	CASE(PT_MV_LONG, LONG_ARRAY, g_uint32_a);
	case PT_MV_CURRENCY:
	case PT_MV_SYSTIME:
	CASE(PT_MV_I8, LONGLONG_ARRAY, g_uint64_a);
	CASE(PT_MV_FLOAT, FLOAT_ARRAY, g_float_a);
	case PT_MV_APPTIME:
	CASE(PT_MV_DOUBLE, DOUBLE_ARRAY, g_double_a);
	CASE(PT_MV_STRING8, STRING_ARRAY, g_str_a);
	CASE(PT_MV_UNICODE, STRING_ARRAY, g_wstr_a);
	CASE(PT_MV_CLSID, GUID_ARRAY, g_guid_a);
	CASE(PT_MV_BINARY, BINARY_ARRAY, g_bin_a);
	default:
		return m_flags & EXT_FLAG_ABK ? EXT_ERR_FORMAT : EXT_ERR_BAD_SWITCH;
	}
#undef CASE
}

int EXT_PULL::g_typed_pv(TYPED_PROPVAL *r)
{
	TRY(g_uint16(&r->type));
	return g_propval(r->type, &r->pvalue);
}

int EXT_PULL::g_tagged_pv(TAGGED_PROPVAL *r)
{
	TRY(g_uint32(&r->proptag));
	return g_propval(PROP_TYPE(r->proptag), &r->pvalue);
}

int EXT_PULL::g_longterm(LONG_TERM_ID *r)
{
	TRY(g_guid(&r->guid));
	TRY(g_bytes(r->global_counter.ab, 6));
	return g_uint16(&r->padding);
}

int EXT_PULL::g_longterm_rang(LONG_TERM_ID_RANGE *r)
{
	TRY(g_longterm(&r->min));
	return g_longterm(&r->max);
}

int EXT_PULL::g_proptag_a(PROPTAG_ARRAY *r)
{
	TRY(g_uint16(&r->count));
	if (r->count == 0) {
		r->pproptag = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pproptag = anew<uint32_t>(strange_roundup(r->count, SR_GROW_PROPTAG_ARRAY));
	if (r->pproptag == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(g_uint32(&r->pproptag[i]));
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
	
	TRY(g_uint8(&r->kind));
	TRY(g_guid(&r->guid));
	r->lid = 0;
	r->pname = NULL;
	if (r->kind == MNID_ID) {
		TRY(g_uint32(&r->lid));
	} else if (r->kind == MNID_STRING) {
		TRY(g_uint8(&name_size));
		if (name_size < 2)
			return EXT_ERR_FORMAT;
		uint32_t offset = m_offset + name_size;
		TRY(g_wstr(&r->pname));
		if (m_offset > offset)
			return EXT_ERR_FORMAT;
		m_offset = offset;
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_propname_a(PROPNAME_ARRAY *r)
{
	TRY(g_uint16(&r->count));
	if (r->count == 0) {
		r->ppropname = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppropname = anew<PROPERTY_NAME>(r->count);
	if (r->ppropname == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(g_propname(&r->ppropname[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_propid_a(PROPID_ARRAY *r)
{
	TRY(g_uint16(&r->count));
	if (r->count == 0) {
		r->ppropid = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppropid = anew<uint16_t>(r->count);
	if (r->ppropid == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(g_uint16(&r->ppropid[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_tpropval_a(TPROPVAL_ARRAY *r)
{
	TRY(g_uint16(&r->count));
	if (r->count == 0) {
		r->ppropval = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppropval = anew<TAGGED_PROPVAL>(strange_roundup(r->count, SR_GROW_TAGGED_PROPVAL));
	if (r->ppropval == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(g_tagged_pv(&r->ppropval[i]));
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
	TRY(g_uint32(&r->count));
	if (r->count == 0) {
		r->pparray = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pparray = anew<TPROPVAL_ARRAY *>(strange_roundup(r->count, SR_GROW_TPROPVAL_ARRAY));
	if (r->pparray == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i) {
		r->pparray[i] = anew<TPROPVAL_ARRAY>();
		if (r->pparray[i] == nullptr)
			return EXT_ERR_ALLOC;
		TRY(g_tpropval_a(r->pparray[i]));
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
	TRY(g_uint16(&r->count));
	r->pproblem = anew<PROPERTY_PROBLEM>(r->count);
	if (r->pproblem == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(ext_buffer_pull_property_problem(this, &r->pproblem[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_xid(uint8_t size, XID *pxid)
{
	if (size < 17 || size > 24)
		return EXT_ERR_FORMAT;
	TRY(g_guid(&pxid->guid));
	return g_bytes(pxid->local_id, size - 16);
}

int EXT_PULL::g_folder_eid(FOLDER_ENTRYID *r)
{
	TRY(g_uint32(&r->flags));
	TRY(g_guid(&r->provider_uid));
	TRY(g_uint16(&r->folder_type));
	TRY(g_guid(&r->database_guid));
	TRY(g_bytes(r->global_counter.ab, 6));
	return g_bytes(r->pad, 2);
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
	TRY(g_uint32(&r->flags));
	TRY(g_guid(&r->provider_uid));
	TRY(g_uint16(&r->message_type));
	TRY(g_guid(&r->folder_database_guid));
	TRY(g_bytes(r->folder_global_counter.ab, 6));
	TRY(g_bytes(r->pad1, 2));
	TRY(g_guid(&r->message_database_guid));
	TRY(g_bytes(r->message_global_counter.ab, 6));
	return g_bytes(r->pad2, 2);
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
	if (r->ppropval == nullptr) {
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
	if (r->pblock == nullptr) {
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
	TRY(g_uint32(&r->count));
	if (r->count == 0)
		return EXT_ERR_FORMAT;
	r->pblock = anew<EXT_ACTION_BLOCK>(r->count);
	if (r->pblock == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(ext_buffer_pull_ext_action_block(this, &r->pblock[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_namedprop_info(NAMEDPROPERTY_INFOMATION *r)
{
	uint32_t size;
	
	TRY(g_uint16(&r->count));
	if (r->count == 0) {
		r->ppropid = NULL;
		r->ppropname = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppropid = anew<uint16_t>(r->count);
	if (r->ppropid == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	r->ppropname = anew<PROPERTY_NAME>(r->count);
	if (r->ppropname == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(g_uint16(&r->ppropid[i]));
	TRY(g_uint32(&size));
	uint32_t offset = m_offset + size;
	for (size_t i = 0; i < r->count; ++i)
		TRY(g_propname(&r->ppropname[i]));
	if (offset < m_offset)
		return EXT_ERR_FORMAT;
	m_offset = offset;
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_flagged_pv(uint16_t type, FLAGGED_PROPVAL *r)
{
	void **ppvalue;
	
	if (type == PT_UNSPECIFIED) {
		/* MS-OXCDATA v17 §2.11.6 FlaggedPropertyValueWithType */
		TRY(g_uint16(&type));
		r->pvalue = anew<TYPED_PROPVAL>();
		if (r->pvalue == nullptr)
			return EXT_ERR_ALLOC;
		((TYPED_PROPVAL*)r->pvalue)->type = type;
		ppvalue = &((TYPED_PROPVAL*)r->pvalue)->pvalue;
	} else {
		ppvalue = &r->pvalue;
	}
	TRY(g_uint8(&r->flag));
	switch (r->flag) {
	case FLAGGED_PROPVAL_FLAG_AVAILABLE:
		return g_propval(type, ppvalue);
	case FLAGGED_PROPVAL_FLAG_UNAVAILABLE:
		*ppvalue = NULL;
		return EXT_ERR_SUCCESS;
	case FLAGGED_PROPVAL_FLAG_ERROR:
		*ppvalue = anew<uint32_t>();
		if (*ppvalue == nullptr)
			return EXT_ERR_ALLOC;
		return g_uint32(static_cast<uint32_t *>(*ppvalue));
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int EXT_PULL::g_proprow(const PROPTAG_ARRAY *pcolumns, PROPERTY_ROW *r)
{
	TRY(g_uint8(&r->flag));
	r->pppropval = anew<void *>(pcolumns->count);
	if (r->pppropval == nullptr)
		return EXT_ERR_ALLOC;
	if (PROPERTY_ROW_FLAG_NONE == r->flag) {
		for (size_t i = 0; i < pcolumns->count; ++i)
			TRY(g_propval(PROP_TYPE(pcolumns->pproptag[i]), &r->pppropval[i]));
		return EXT_ERR_SUCCESS;
	} else if (PROPERTY_ROW_FLAG_FLAGGED == r->flag) {
		for (size_t i = 0; i < pcolumns->count; ++i) {
			r->pppropval[i] = anew<FLAGGED_PROPVAL>();
			if (r->pppropval[i] == nullptr)
				return EXT_ERR_ALLOC;
			TRY(g_flagged_pv(PROP_TYPE(pcolumns->pproptag[i]),
			         static_cast<FLAGGED_PROPVAL *>(r->pppropval[i])));
		}
		return EXT_ERR_SUCCESS;
	}
	return EXT_ERR_BAD_SWITCH;
}

int EXT_PULL::g_sortorder(SORT_ORDER *r)
{
	TRY(g_uint16(&r->type));
	if ((r->type & MVI_FLAG) == MV_FLAG)
		/* MV_FLAG set without MV_INSTANCE */
		return EXT_ERR_FORMAT;
	TRY(g_uint16(&r->propid));
	return g_uint8(&r->table_sort);
}

int EXT_PULL::g_sortorder_set(SORTORDER_SET *r)
{
	TRY(g_uint16(&r->count));
	TRY(g_uint16(&r->ccategories));
	TRY(g_uint16(&r->cexpanded));
	if (r->count == 0 || r->ccategories > r->count || r->cexpanded > r->ccategories)
		return EXT_ERR_FORMAT;
	r->psort = anew<SORT_ORDER>(r->count);
	if (r->psort == nullptr) {
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
	
	TRY(g_uint16(&r->flags));
	type = r->flags & 0x0007;
	b_unicode = FALSE;
	if (r->flags & RECIPIENT_ROW_FLAG_UNICODE)
		b_unicode = TRUE;
	r->pprefix_used = NULL;
	r->have_display_type = false;
	r->px500dn = NULL;
	if (RECIPIENT_ROW_TYPE_X500DN == type) {
		r->pprefix_used = anew<uint8_t>();
		if (r->pprefix_used == nullptr)
			return EXT_ERR_ALLOC;
		TRY(g_uint8(r->pprefix_used));
		TRY(g_uint8(&r->display_type));
		r->have_display_type = true;
		TRY(g_str(&r->px500dn));
	}
	r->pentry_id = NULL;
	r->psearch_key = NULL;
	if (RECIPIENT_ROW_TYPE_PERSONAL_DLIST1 == type ||
		RECIPIENT_ROW_TYPE_PERSONAL_DLIST2 == type) {
		r->pentry_id = anew<BINARY>();
		if (r->pentry_id == nullptr)
			return EXT_ERR_ALLOC;
		TRY(g_bin(r->pentry_id));
		r->psearch_key = anew<BINARY>();
		if (r->psearch_key == nullptr)
			return EXT_ERR_ALLOC;
		TRY(g_bin(r->psearch_key));
	}
	r->paddress_type = NULL;
	if (type == RECIPIENT_ROW_TYPE_NONE &&
	    (r->flags & RECIPIENT_ROW_FLAG_OUTOFSTANDARD))
		TRY(g_str(&r->paddress_type));
	r->pmail_address = NULL;
	if (RECIPIENT_ROW_FLAG_EMAIL & r->flags) {
		if (b_unicode)
			TRY(g_wstr(&r->pmail_address));
		else
			TRY(g_str(&r->pmail_address));
	}
	r->pdisplay_name = NULL;
	if (r->flags & RECIPIENT_ROW_FLAG_DISPLAY) {
		if (b_unicode)
			TRY(g_wstr(&r->pdisplay_name));
		else
			TRY(g_str(&r->pdisplay_name));
	}
	r->psimple_name = NULL;
	if (r->flags & RECIPIENT_ROW_FLAG_SIMPLE) {
		if (b_unicode)
			TRY(g_wstr(&r->psimple_name));
		else
			TRY(g_str(&r->psimple_name));
	}
	r->ptransmittable_name = NULL;
	if (r->flags & RECIPIENT_ROW_FLAG_TRANSMITTABLE) {
		if (b_unicode)
			TRY(g_wstr(&r->ptransmittable_name));
		else
			TRY(g_str(&r->ptransmittable_name));
	}
	if (RECIPIENT_ROW_FLAG_SAME == r->flags) {
		if (r->pdisplay_name == nullptr && r->ptransmittable_name != nullptr)
			r->pdisplay_name = r->ptransmittable_name;
		else if (r->pdisplay_name != nullptr && r->ptransmittable_name == nullptr)
			r->ptransmittable_name = r->pdisplay_name;
	}
	TRY(g_uint16(&r->count));
	if (r->count > pproptags->count)
		return EXT_ERR_FORMAT;
	proptags.count = r->count;
	proptags.pproptag = (uint32_t*)pproptags->pproptag;
	return g_proprow(&proptags, &r->properties);
}

int EXT_PULL::g_modrcpt_row(PROPTAG_ARRAY *pproptags, MODIFYRECIPIENT_ROW *r)
{
	uint16_t row_size;
	
	TRY(g_uint32(&r->row_id));
	TRY(g_uint8(&r->recipient_type));
	TRY(g_uint16(&row_size));
	if (row_size == 0) {
		r->precipient_row = NULL;
		return EXT_ERR_SUCCESS;
	}
	uint32_t offset = m_offset + row_size;
	r->precipient_row = anew<RECIPIENT_ROW>();
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
	TRY(g_uint8(&r->flags));
	return g_tpropval_a(&r->propvals);
}

int EXT_PULL::g_rule_data(RULE_DATA *r)
{
	TRY(g_uint8(&r->flags));
	return g_tpropval_a(&r->propvals);
}

int EXT_PULL::g_abk_eid(EMSAB_ENTRYID *r)
{
	FLATUID g;
	TRY(g_uint32(&r->flags));
	TRY(g_guid(&g));
	if (g != muidEMSAB)
		return EXT_ERR_FORMAT;
	TRY(g_uint32(&r->version));
	TRY(g_uint32(&r->type));
	return g_str(&r->px500dn);
}

int EXT_PULL::g_oneoff_eid(ONEOFF_ENTRYID *r)
{
	FLATUID g;
	TRY(g_uint32(&r->flags));
	TRY(g_guid(&g));
	if (g != muidOOP)
		return EXT_ERR_FORMAT;
	TRY(g_uint16(&r->version));
	TRY(g_uint16(&r->ctrl_flags));
	if (r->ctrl_flags & CTRL_FLAG_UNICODE) {
		TRY(g_wstr(&r->pdisplay_name));
		TRY(g_wstr(&r->paddress_type));
		return g_wstr(&r->pmail_address);
	} else {
		TRY(g_str(&r->pdisplay_name));
		TRY(g_str(&r->paddress_type));
		return g_str(&r->pmail_address);
	}
}

int EXT_PULL::g_flatentry_a(BINARY_ARRAY *r)
{
	uint32_t bytes;
	uint8_t pad_len;
	
	TRY(g_uint32(&r->count));
	r->pbin = anew<BINARY>(r->count);
	if (r->pbin == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	TRY(g_uint32(&bytes));
	uint32_t offset = m_offset + bytes;
	for (size_t i = 0; i < r->count; ++i) {
		TRY(g_bin(&r->pbin[i]));
		if (m_offset > offset)
			return EXT_ERR_FORMAT;
		bytes = r->pbin[i].cb;
		pad_len = ((bytes + 3) & ~3) - bytes;
		TRY(advance(pad_len));
	}
	if (m_offset > offset)
		return EXT_ERR_FORMAT;
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_eid_a(EID_ARRAY *r)
{
	TRY(g_uint32(&r->count));
	if (r->count == 0) {
		r->pids = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pids = anew<uint64_t>(r->count);
	if (r->pids == nullptr) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(g_uint64(&r->pids[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PULL::g_systime(SYSTEMTIME *r)
{
	TRY(g_int16(&r->year));
	TRY(g_int16(&r->month));
	TRY(g_int16(&r->dayofweek));
	TRY(g_int16(&r->day));
	TRY(g_int16(&r->hour));
	TRY(g_int16(&r->minute));
	TRY(g_int16(&r->second));
	return g_int16(&r->milliseconds);
}

int EXT_PULL::g_tzstruct(TIMEZONESTRUCT *r)
{
	TRY(g_int32(&r->bias));
	TRY(g_int32(&r->standardbias));
	TRY(g_int32(&r->daylightbias));
	TRY(g_int16(&r->standardyear));
	TRY(g_systime(&r->standarddate));
	TRY(g_int16(&r->daylightyear));
	return g_systime(&r->daylightdate);
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
	
	TRY(g_uint8(&r->major));
	TRY(g_uint8(&r->minor));
	TRY(g_uint16(&cbheader));
	if (cbheader > 266)
		return EXT_ERR_FORMAT;
	TRY(g_uint16(&r->reserved));
	TRY(g_uint16(&cchkeyname));
	if (cbheader != 6 + 2 * cchkeyname)
		return EXT_ERR_FORMAT;
	memset(tmp_buff, 0, sizeof(tmp_buff));
	TRY(g_bytes(tmp_buff, cbheader - 6));
	if (!utf16le_to_utf8(tmp_buff, cbheader - 4, tmp_buff1, arsizeof(tmp_buff1)))
		return EXT_ERR_CHARCNV;
	r->keyname = anew<char>(strlen(tmp_buff1) + 1);
	if (r->keyname == nullptr)
		return EXT_ERR_ALLOC;
	strcpy(r->keyname, tmp_buff1);
	TRY(g_uint16(&r->crules));
	r->prules = anew<TZRULE>(r->crules);
	if (r->prules == nullptr) {
		r->crules = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->crules; ++i)
		TRY(ext_buffer_pull_tzrule(this, &r->prules[i]));
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
	if (r->deletedinstancecount == 0) {
		r->pdeletedinstancedates = NULL;
	} else {
		r->pdeletedinstancedates = pext->anew<uint32_t>(r->deletedinstancecount);
		if (r->pdeletedinstancedates == nullptr) {
			r->deletedinstancecount = 0;
			return EXT_ERR_ALLOC;
		}
	}
	for (size_t i = 0; i < r->deletedinstancecount; ++i)
		TRY(pext->g_uint32(&r->pdeletedinstancedates[i]));
	TRY(pext->g_uint32(&r->modifiedinstancecount));
	if (r->modifiedinstancecount == 0) {
		r->pmodifiedinstancedates = NULL;
	} else {
		r->pmodifiedinstancedates = pext->anew<uint32_t>(r->modifiedinstancecount);
		if (r->pmodifiedinstancedates == nullptr) {
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
	if (r->overrideflags & ARO_SUBJECT) {
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
	if (r->overrideflags & ARO_MEETINGTYPE)
		TRY(pext->g_uint32(&r->meetingtype));
	if (r->overrideflags & ARO_REMINDERDELTA)
		TRY(pext->g_uint32(&r->reminderdelta));
	if (r->overrideflags & ARO_REMINDER)
		TRY(pext->g_uint32(&r->reminderset));
	if (r->overrideflags & ARO_LOCATION) {
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
	if (r->overrideflags & ARO_BUSYSTATUS)
		TRY(pext->g_uint32(&r->busystatus));
	if (r->overrideflags & ARO_ATTACHMENT)
		TRY(pext->g_uint32(&r->attachment));
	if (r->overrideflags & ARO_SUBTYPE)
		TRY(pext->g_uint32(&r->subtype));
	if (r->overrideflags & ARO_APPTCOLOR)
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
	if (r->preserved == nullptr) {
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
	if (r->reservedblockee1size == 0) {
		r->preservedblockee1 = NULL;
	} else {
		r->preservedblockee1 = pext->anew<uint8_t>(r->reservedblockee1size);
		if (r->preservedblockee1 == nullptr) {
			r->reservedblockee1size = 0;
			return EXT_ERR_ALLOC;
		}
		TRY(pext->g_bytes(r->preservedblockee1, r->reservedblockee1size));
	}
	if (overrideflags & (ARO_LOCATION | ARO_SUBJECT)) {
		TRY(pext->g_uint32(&r->startdatetime));
		TRY(pext->g_uint32(&r->enddatetime));
		TRY(pext->g_uint32(&r->originalstartdate));
	}
	if (overrideflags & ARO_SUBJECT) {
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
	if (overrideflags & ARO_LOCATION) {
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
	if (overrideflags & (ARO_SUBJECT | ARO_LOCATION)) {
		TRY(pext->g_uint32(&r->reservedblockee2size));
		if (r->reservedblockee2size == 0) {
			r->preservedblockee2 = NULL;
		} else {
			r->preservedblockee2 = pext->anew<uint8_t>(r->reservedblockee2size);
			if (r->preservedblockee2 == nullptr) {
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
	TRY(ext_buffer_pull_recurrencepattern(this, &r->recur_pat));
	TRY(g_uint32(&r->readerversion2));
	TRY(g_uint32(&r->writerversion2));
	TRY(g_uint32(&r->starttimeoffset));
	TRY(g_uint32(&r->endtimeoffset));
	TRY(g_uint16(&r->exceptioncount));
	if (r->exceptioncount == 0) {
		r->pexceptioninfo = NULL;
		r->pextendedexception = NULL;
	} else {
		r->pexceptioninfo = anew<EXCEPTIONINFO>(r->exceptioncount);
		if (r->pexceptioninfo == nullptr) {
			r->exceptioncount = 0;
			return EXT_ERR_ALLOC;
		}
		r->pextendedexception = anew<EXTENDEDEXCEPTION>(r->exceptioncount);
		if (r->pextendedexception == nullptr) {
			r->exceptioncount = 0;
			return EXT_ERR_ALLOC;
		}
	}
	for (size_t i = 0; i < r->exceptioncount; ++i)
		TRY(ext_buffer_pull_exceptioninfo(this, &r->pexceptioninfo[i]));
	TRY(g_uint32(&r->reservedblock1size));
	if (r->reservedblock1size == 0) {
		r->preservedblock1 = NULL;
	} else {
		r->preservedblock1 = anew<uint8_t>(r->reservedblock1size);
		if (r->preservedblock1 == nullptr) {
			r->reservedblock1size = 0;
			return EXT_ERR_ALLOC;
		}
		TRY(g_bytes(r->preservedblock1, r->reservedblock1size));
	}
	for (size_t i = 0; i < r->exceptioncount; ++i)
		TRY(ext_buffer_pull_extendedexception(this, r->writerversion2, r->pexceptioninfo[i].overrideflags, &r->pextendedexception[i]));
	TRY(g_uint32(&r->reservedblock2size));
	if (r->reservedblock2size == 0) {
		r->preservedblock2 = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->preservedblock2 = anew<uint8_t>(r->reservedblock2size);
	if (r->preservedblock2 == nullptr) {
		r->reservedblock2size = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(r->preservedblock2, r->reservedblock2size);
}

int EXT_PULL::g_goid(GLOBALOBJECTID *r)
{
	uint8_t yh;
	uint8_t yl;
	
	TRY(g_guid(&r->arrayid));
	TRY(g_uint8(&yh));
	TRY(g_uint8(&yl));
	r->year = ((uint16_t)yh) << 8 | yl;
	TRY(g_uint8(&r->month));
	TRY(g_uint8(&r->day));
	TRY(g_uint64(&r->creationtime));
	TRY(g_bytes(r->x, 8));
	return g_exbin(&r->data);
}

static int ext_buffer_pull_attachment_list(EXT_PULL *pext, ATTACHMENT_LIST *r)
{
	int i;
	uint8_t tmp_byte;
	
	TRY(pext->g_uint16(&r->count));
	r->pplist = pext->anew<ATTACHMENT_CONTENT *>(strange_roundup(r->count, SR_GROW_ATTACHMENT_CONTENT));
	if (r->pplist == nullptr) {
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
	
	TRY(g_tpropval_a(&r->proplist));
	TRY(g_uint8(&tmp_byte));
	if (0 != tmp_byte) {
		r->children.prcpts = anew<TARRAY_SET>();
		if (r->children.prcpts == nullptr)
			return EXT_ERR_ALLOC;
		TRY(g_tarray_set(r->children.prcpts));
	} else {
		r->children.prcpts = NULL;
	}
	TRY(g_uint8(&tmp_byte));
	if (0 != tmp_byte) {
		r->children.pattachments = anew<ATTACHMENT_LIST>();
		if (r->children.pattachments == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_attachment_list(this, r->children.pattachments);
	}
	r->children.pattachments = NULL;
	return EXT_ERR_SUCCESS;
}

BOOL EXT_PUSH::init(void *pdata, uint32_t alloc_size,
    uint32_t flags, const EXT_BUFFER_MGT *mgt)
{
	const EXT_BUFFER_MGT default_mgt = {malloc, realloc, free};
	m_mgt = mgt != nullptr ? *mgt : default_mgt;
	if (pdata == nullptr) {
		b_alloc = TRUE;
		m_alloc_size = 8192;
		m_udata = static_cast<uint8_t *>(m_mgt.alloc(m_alloc_size));
		if (m_udata == nullptr) {
			m_alloc_size = 0;
			return FALSE;
		}
	} else {
		b_alloc = FALSE;
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

int EXT_PUSH::p_rpchdr(const RPC_HEADER_EXT &r)
{
	TRY(p_uint16(r.version));
	TRY(p_uint16(r.flags));
	TRY(p_uint16(r.size));
	return p_uint16(r.size_actual);
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
	if (!check_ovf(size))
		return EXT_ERR_BUFSIZE;
	m_offset += size;
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_bytes(const void *pdata, uint32_t n)
{
	if (n == 0)
		/*
		 * Covers pdata==nullptr case as far as we care. If
		 * pdata==nullptr and n>0, memcpy/ASAN will usually crash/exit.
		 */
		return EXT_ERR_SUCCESS;
	if (!check_ovf(n))
		return EXT_ERR_BUFSIZE;
	memcpy(&m_udata[m_offset], pdata, n);
	m_offset += n;
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_uint8(uint8_t v)
{
	if (!check_ovf(sizeof(uint8_t)))
		return EXT_ERR_BUFSIZE;
	m_udata[m_offset] = v;
	m_offset += sizeof(uint8_t);
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_uint16(uint16_t v)
{
	if (!check_ovf(sizeof(uint16_t)))
		return EXT_ERR_BUFSIZE;
	cpu_to_le16p(&m_udata[m_offset], v);
	m_offset += sizeof(uint16_t);
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_uint32(uint32_t v)
{
	if (!check_ovf(sizeof(uint32_t)))
		return EXT_ERR_BUFSIZE;
	cpu_to_le32p(&m_udata[m_offset], v);
	m_offset += sizeof(uint32_t);
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_uint64(uint64_t v)
{
	if (!check_ovf(sizeof(uint64_t)))
		return EXT_ERR_BUFSIZE;
	cpu_to_le64p(&m_udata[m_offset], v);
	m_offset += sizeof(uint64_t);
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_float(float v)
{
	if (!check_ovf(sizeof(float)))
		return EXT_ERR_BUFSIZE;
	memcpy(&m_udata[m_offset], &v, sizeof(v));
	m_offset += sizeof(float);
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_double(double v)
{
	static_assert(sizeof(v) == 8 && CHAR_BIT == 8, "");
	if (!check_ovf(sizeof(double)))
		return EXT_ERR_BUFSIZE;
	memcpy(&m_udata[m_offset], &v, sizeof(v));
	m_offset += sizeof(double);
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_bool(BOOL v)
{
	if (!check_ovf(sizeof(uint8_t)))
		return EXT_ERR_BUFSIZE;
	m_udata[m_offset] = !!v;
	m_offset += sizeof(uint8_t);
	return EXT_ERR_SUCCESS;
	
}

int EXT_PUSH::p_bin(const BINARY &r)
{
	if (m_flags & EXT_FLAG_WCOUNT) {
		TRY(p_uint32(r.cb));
	} else {
		if (r.cb > 0xFFFF)
			return EXT_ERR_FORMAT;
		TRY(p_uint16(r.cb));
	}
	if (r.cb == 0)
		return EXT_ERR_SUCCESS;
	return p_bytes(r.pb, r.cb);
}

int EXT_PUSH::p_bin_s(const BINARY &r)
{
	if (r.cb > 0xFFFF)
		return EXT_ERR_FORMAT;
	TRY(p_uint16(r.cb));
	if (r.cb == 0)
		return EXT_ERR_SUCCESS;
	return p_bytes(r.pb, r.cb);
}

int EXT_PUSH::p_bin_ex(const BINARY &r)
{
	TRY(p_uint32(r.cb));
	if (r.cb == 0)
		return EXT_ERR_SUCCESS;
	return p_bytes(r.pb, r.cb);
}

int EXT_PUSH::p_guid(const GUID &r)
{
	TRY(p_uint32(r.time_low));
	TRY(p_uint16(r.time_mid));
	TRY(p_uint16(r.time_hi_and_version));
	TRY(p_bytes(r.clock_seq, 2));
	return p_bytes(r.node, 6);
}

int EXT_PUSH::p_str(const char *pstr)
{
	size_t len = strlen(pstr);
	if (m_flags & EXT_FLAG_TBLLMT) {
		if (len > 509) {
			TRY(p_bytes(pstr, 509));
			return p_uint8(0);
		}
	}
	return p_bytes(pstr, len + 1);
}

int EXT_PUSH::p_wstr(const char *pstr)
{
	if (!(m_flags & EXT_FLAG_UTF16))
		return p_str(pstr);
	auto len = utf8_to_utf16_len(pstr);
	std::unique_ptr<char[]> pbuff;
	try {
		pbuff = std::make_unique<char[]>(len);
	} catch (const std::bad_alloc &) {
		return EXT_ERR_ALLOC;
	}
	auto utf16_len = utf8_to_utf16le(pstr, pbuff.get(), len);
	if (utf16_len < 2) {
		pbuff[0] = '\0';
		pbuff[1] = '\0';
		len = 2;
	} else {
		len = utf16_len;
	}
	if (m_flags & EXT_FLAG_TBLLMT) {
		if (len > 510) {
			len = 510;
			pbuff[508] = '\0';
			pbuff[509] = '\0';
		}
	}
	return p_bytes(pbuff.get(), len);
}

int EXT_PUSH::p_uint16_a(const SHORT_ARRAY &r)
{
	TRY(p_uint32(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(p_uint16(r.ps[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_uint32_a(const LONG_ARRAY &r)
{
	TRY(p_uint32(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(p_uint32(r.pl[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_uint64_a(const LONGLONG_ARRAY &r)
{
	TRY(p_uint32(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(p_uint64(r.pll[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_uint64_sa(const LONGLONG_ARRAY &r)
{
	if (r.count > 0xFFFF)
		return EXT_ERR_FORMAT;
	TRY(p_uint16(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(p_uint64(r.pll[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_float_a(const FLOAT_ARRAY &r)
{
	TRY(p_uint32(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(p_float(r.mval[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_double_a(const DOUBLE_ARRAY &r)
{
	TRY(p_uint32(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(p_double(r.mval[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_bin_a(const BINARY_ARRAY &r)
{
	TRY(p_uint32(r.count));
	for (size_t i = 0; i < r.count; ++i) {
		if (m_flags & EXT_FLAG_ABK) {
			if (r.pbin[i].cb == 0) {
				TRY(p_uint8(0));
				continue;
			}
			TRY(p_uint8(0xFF));
		}
		TRY(p_bin(r.pbin[i]));
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_str_a(const STRING_ARRAY &r)
{
	TRY(p_uint32(r.count));
	for (size_t i = 0; i < r.count; ++i) {
		if (m_flags & EXT_FLAG_ABK) {
			if (r.ppstr[i] == nullptr) {
				TRY(p_uint8(0));
				continue;
			}
			TRY(p_uint8(0xFF));
		}
		TRY(p_str(r.ppstr[i]));
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_wstr_a(const STRING_ARRAY &r)
{
	TRY(p_uint32(r.count));
	for (size_t i = 0; i < r.count; ++i) {
		if (m_flags & EXT_FLAG_ABK) {
			if (r.ppstr[i] == nullptr) {
				TRY(p_uint8(0));
				continue;
			}
			TRY(p_uint8(0xFF));
		}
		TRY(p_wstr(r.ppstr[i]));
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_guid_a(const GUID_ARRAY &r)
{
	TRY(p_uint32(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(p_guid(r.pguid[i]));
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
		TRY(pext->p_restriction(r->pres[i]));
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_restriction_not(
	EXT_PUSH *pext, const RESTRICTION_NOT *r)
{
	return pext->p_restriction(r->res);
}

static int ext_buffer_push_restriction_content(
	EXT_PUSH *pext, const RESTRICTION_CONTENT *r)
{
	TRY(pext->p_uint32(r->fuzzy_level));
	TRY(pext->p_uint32(r->proptag));
	return pext->p_tagged_pv(r->propval);
}

static int ext_buffer_push_restriction_property(
	EXT_PUSH *pext, const RESTRICTION_PROPERTY *r)
{
	TRY(pext->p_uint8(r->relop));
	TRY(pext->p_uint32(r->proptag));
	return pext->p_tagged_pv(r->propval);
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
	return pext->p_restriction(r->res);
}

static int ext_buffer_push_restriction_comment(
	EXT_PUSH *pext, const RESTRICTION_COMMENT *r)
{
	if (r->count == 0)
		return EXT_ERR_FORMAT;
	TRY(pext->p_uint8(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->p_tagged_pv(r->ppropval[i]));
	if (NULL != r->pres) {
		TRY(pext->p_uint8(1));
		return pext->p_restriction(*r->pres);
	}
	return pext->p_uint8(0);
}

static int ext_buffer_push_restriction_count(
	EXT_PUSH *pext, const RESTRICTION_COUNT *r)
{
	TRY(pext->p_uint32(r->count));
	return pext->p_restriction(r->sub_res);
}

int EXT_PUSH::p_restriction(const RESTRICTION &r)
{
	TRY(p_uint8(r.rt));
	switch (r.rt) {
	case RES_AND:
	case RES_OR:
		return ext_buffer_push_restriction_and_or(this, r.andor);
	case RES_NOT:
		return ext_buffer_push_restriction_not(this, r.xnot);
	case RES_CONTENT:
		return ext_buffer_push_restriction_content(this, r.cont);
	case RES_PROPERTY:
		return ext_buffer_push_restriction_property(this, r.prop);
	case RES_PROPCOMPARE:
		return ext_buffer_push_restriction_propcompare(this, r.pcmp);
	case RES_BITMASK:
		return ext_buffer_push_restriction_bitmask(this, r.bm);
	case RES_SIZE:
		return ext_buffer_push_restriction_size(this, r.size);
	case RES_EXIST:
		return ext_buffer_push_restriction_exist(this, r.exist);
	case RES_SUBRESTRICTION:
		return ext_buffer_push_restriction_subobj(this, r.sub);
	case RES_COMMENT:
	case RES_ANNOTATION:
		return ext_buffer_push_restriction_comment(this, r.comment);
	case RES_COUNT:
		return ext_buffer_push_restriction_count(this, r.count);
	case RES_NULL:
		return EXT_ERR_SUCCESS;
	}
	return EXT_ERR_BAD_SWITCH;
}

int EXT_PUSH::p_svreid(const SVREID &r)
{
	if (r.pbin != nullptr) {
		TRY(p_uint16(r.pbin->cb + 1));
		TRY(p_uint8(0));
		return p_bytes(r.pbin->pb, r.pbin->cb);
	}
	TRY(p_uint16(21));
	TRY(p_uint8(1));
	TRY(p_uint64(r.folder_id));
	TRY(p_uint64(r.message_id));
	return p_uint32(r.instance);
}

int EXT_PUSH::p_store_eid(const STORE_ENTRYID &r)
{
	TRY(p_uint32(r.flags));
	TRY(p_guid(muidStoreWrap));
	TRY(p_uint8(r.version));
	TRY(p_uint8(r.flag));
	constexpr char dll[14] = "emsmdb.dll";
	TRY(p_bytes(dll, arsizeof(dll)));
	TRY(p_uint32(r.wrapped_flags));
	TRY(p_guid(r.wrapped_provider_uid));
	TRY(p_uint32(r.wrapped_type));
	TRY(p_str(r.pserver_name));
	return p_str(r.pmailbox_dn);
}

static int ext_buffer_push_zmovecopy_action(EXT_PUSH *e,
    const ZMOVECOPY_ACTION *r)
{
	TRY(e->p_bin(r->store_eid));
	return e->p_bin(r->folder_eid);
}

static int ext_buffer_push_movecopy_action(EXT_PUSH *pext,
    const MOVECOPY_ACTION *r)
{
	auto &ext = *pext;
	uint16_t eid_size;
	
	TRY(pext->p_uint8(r->same_store));
	if (r->same_store == 0) {
		uint32_t offset = ext.m_offset;
		TRY(pext->advance(sizeof(uint16_t)));
		if (r->pstore_eid == nullptr)
			return EXT_ERR_FORMAT;
		TRY(pext->p_store_eid(*r->pstore_eid));
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
		return pext->p_svreid(*static_cast<SVREID *>(r->pfolder_eid));
	else
		return pext->p_bin(*static_cast<BINARY *>(r->pfolder_eid));
}

static int ext_buffer_push_zreply_action(EXT_PUSH *e, const ZREPLY_ACTION *r)
{
	TRY(e->p_bin(r->message_eid));
	return e->p_guid(r->template_guid);
}

static int ext_buffer_push_reply_action(
	EXT_PUSH *pext, const REPLY_ACTION *r)
{
	TRY(pext->p_uint64(r->template_folder_id));
	TRY(pext->p_uint64(r->template_message_id));
	return pext->p_guid(r->template_guid);
}

static int ext_buffer_push_recipient_block(
	EXT_PUSH *pext, const RECIPIENT_BLOCK *r)
{
	if (r->count == 0)
		return EXT_ERR_FORMAT;
	TRY(pext->p_uint8(r->reserved));
	TRY(pext->p_uint16(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(pext->p_tagged_pv(r->ppropval[i]));
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
		TRY(pext->p_tagged_pv(*static_cast<TAGGED_PROPVAL *>(r->pdata)));
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

int EXT_PUSH::p_rule_actions(const RULE_ACTIONS &r)
{
	if (r.count == 0)
		return EXT_ERR_FORMAT;
	TRY(p_uint16(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(ext_buffer_push_action_block(this, &r.pblock[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_propval(uint16_t type, const void *pval)
{
	if (m_flags & EXT_FLAG_ABK && (type == PT_STRING8 ||
	    type == PT_UNICODE || type == PT_BINARY || (type & MV_FLAG))) {
		if (pval == nullptr)
			return p_uint8(0);
		TRY(p_uint8(0xFF));
	} else if ((type & MVI_FLAG) == MVI_FLAG) {
		/* convert multi-value instance into single value */
		type &= ~MVI_FLAG;
	}
#define CASE(mt, ct, fu) \
	case (mt): return fu(*static_cast<const ct *>(pval));

	switch (type) {
	CASE(PT_UNSPECIFIED, TYPED_PROPVAL, p_typed_pv);
	CASE(PT_SHORT, uint16_t, p_uint16);
	case PT_ERROR:
	CASE(PT_LONG, uint32_t, p_uint32);
	CASE(PT_FLOAT, float, p_float);
	case PT_APPTIME:
	CASE(PT_DOUBLE, double, p_double);
	CASE(PT_BOOLEAN, uint8_t, p_uint8);
	case PT_CURRENCY:
	case PT_SYSTIME:
	CASE(PT_I8, uint64_t, p_uint64);
	case PT_STRING8:
		return p_str(static_cast<const char *>(pval));
	case PT_UNICODE:
		return p_wstr(static_cast<const char *>(pval));
	CASE(PT_CLSID, GUID, p_guid);
	CASE(PT_SVREID, SVREID, p_svreid);
	CASE(PT_SRESTRICTION, RESTRICTION, p_restriction);
	CASE(PT_ACTIONS, RULE_ACTIONS, p_rule_actions);
	case PT_OBJECT:
	CASE(PT_BINARY, BINARY, p_bin);
	CASE(PT_MV_SHORT, SHORT_ARRAY, p_uint16_a);
	CASE(PT_MV_LONG, LONG_ARRAY, p_uint32_a);
	case PT_MV_CURRENCY:
	case PT_MV_SYSTIME:
	CASE(PT_MV_I8, LONGLONG_ARRAY, p_uint64_a);
	CASE(PT_MV_FLOAT, FLOAT_ARRAY, p_float_a);
	case PT_MV_APPTIME:
	CASE(PT_MV_DOUBLE, DOUBLE_ARRAY, p_double_a);
	CASE(PT_MV_STRING8, STRING_ARRAY, p_str_a);
	CASE(PT_MV_UNICODE, STRING_ARRAY, p_wstr_a);
	CASE(PT_MV_CLSID, GUID_ARRAY, p_guid_a);
	CASE(PT_MV_BINARY, BINARY_ARRAY, p_bin_a);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
#undef CASE
}

int EXT_PUSH::p_typed_pv(const TYPED_PROPVAL &r)
{
	TRY(p_uint16(r.type));
	return p_propval(r.type, r.pvalue);
}

int EXT_PUSH::p_tagged_pv(const TAGGED_PROPVAL &r)
{
	TRY(p_uint32(r.proptag));
	return p_propval(PROP_TYPE(r.proptag), r.pvalue);
}

int EXT_PUSH::p_longterm(const LONG_TERM_ID &r)
{
	TRY(p_guid(r.guid));
	TRY(p_bytes(r.global_counter.ab, 6));
	return p_uint16(r.padding);
}

int EXT_PUSH::p_longterm_a(const LONG_TERM_ID_ARRAY &r)
{
	TRY(p_uint16(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(p_longterm(r.pids[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_proptag_a(const PROPTAG_ARRAY &r)
{
	TRY(p_uint16(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(p_uint32(r.pproptag[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_proptag_a(const LPROPTAG_ARRAY &r)
{
	TRY(p_uint32(r.cvalues));
	for (size_t i = 0; i < r.cvalues; ++i)
		TRY(p_uint32(r.pproptag[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_propname(const PROPERTY_NAME &r)
{
	TRY(p_uint8(r.kind));
	TRY(p_guid(r.guid));
	if (r.kind == MNID_ID) {
		TRY(p_uint32(r.lid));
	} else if (r.kind == MNID_STRING) {
		uint32_t offset = m_offset;
		TRY(advance(sizeof(uint8_t)));
		TRY(p_wstr(r.pname));
		uint8_t name_size = m_offset - (offset + sizeof(uint8_t));
		uint32_t offset1 = m_offset;
		m_offset = offset;
		TRY(p_uint8(name_size));
		m_offset = offset1;
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_propname_a(const PROPNAME_ARRAY &r)
{
	TRY(p_uint16(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(p_propname(r.ppropname[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_propid_a(const PROPID_ARRAY &r)
{
	TRY(p_uint16(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(p_uint16(r.ppropid[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_tpropval_a(const TPROPVAL_ARRAY &r)
{
	TRY(p_uint16(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(p_tagged_pv(r.ppropval[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_tpropval_a(const LTPROPVAL_ARRAY &r)
{
	TRY(p_uint32(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(p_tagged_pv(r.propval[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_tarray_set(const TARRAY_SET &r)
{
	TRY(p_uint32(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(p_tpropval_a(*r.pparray[i]));
	return EXT_ERR_SUCCESS;
}


static int ext_buffer_push_property_problem(EXT_PUSH *pext, const PROPERTY_PROBLEM &r)
{
	TRY(pext->p_uint16(r.index));
	TRY(pext->p_uint32(r.proptag));
	return pext->p_uint32(r.err);
}

int EXT_PUSH::p_problem_a(const PROBLEM_ARRAY &r)
{
	TRY(p_uint16(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(ext_buffer_push_property_problem(this, r.pproblem[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_xid(const XID &xid)
{
	if (xid.size < 17 || xid.size > 24)
		return EXT_ERR_FORMAT;
	TRY(p_guid(xid.guid));
	return p_bytes(xid.local_id, xid.size - 16);
}

int EXT_PUSH::p_folder_eid(const FOLDER_ENTRYID &r)
{
	TRY(p_uint32(r.flags));
	TRY(p_guid(r.provider_uid));
	TRY(p_uint16(r.folder_type));
	TRY(p_guid(r.database_guid));
	TRY(p_bytes(r.global_counter.ab, 6));
	return p_bytes(r.pad, 2);
}

int EXT_PUSH::p_msg_eid(const MESSAGE_ENTRYID &r)
{
	TRY(p_uint32(r.flags));
	TRY(p_guid(r.provider_uid));
	TRY(p_uint16(r.message_type));
	TRY(p_guid(r.folder_database_guid));
	TRY(p_bytes(r.folder_global_counter.ab, 6));
	TRY(p_bytes(r.pad1, 2));
	TRY(p_guid(r.message_database_guid));
	TRY(p_bytes(r.message_global_counter.ab, 6));
	return p_bytes(r.pad2, 2);
}

int EXT_PUSH::p_flagged_pv(uint16_t type, const FLAGGED_PROPVAL &r)
{
	void *pvalue = nullptr;
	
	if (type == PT_UNSPECIFIED && !(m_flags & EXT_FLAG_ABK)) {
		if (FLAGGED_PROPVAL_FLAG_UNAVAILABLE == r.flag) {
			type = 0;
		} else if (FLAGGED_PROPVAL_FLAG_ERROR == r.flag) {
			type = PT_ERROR;
			pvalue = r.pvalue;
		} else {
			type = static_cast<TYPED_PROPVAL *>(r.pvalue)->type;
			pvalue = static_cast<TYPED_PROPVAL *>(r.pvalue)->pvalue;
		}
		TRY(p_uint16(type));
	} else {
		pvalue = r.pvalue;
	}
	TRY(p_uint8(r.flag));
	switch (r.flag) {
	case FLAGGED_PROPVAL_FLAG_AVAILABLE:
		return p_propval(type, pvalue);
	case FLAGGED_PROPVAL_FLAG_UNAVAILABLE:
		return EXT_ERR_SUCCESS;
	case FLAGGED_PROPVAL_FLAG_ERROR:
		return p_uint32(*static_cast<uint32_t *>(pvalue));
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int EXT_PUSH::p_proprow(const PROPTAG_ARRAY &cols, const PROPERTY_ROW &r)
{
	TRY(p_uint8(r.flag));
	if (PROPERTY_ROW_FLAG_NONE == r.flag) {
		for (size_t i = 0; i < cols.count; ++i)
			TRY(p_propval(PROP_TYPE(cols.pproptag[i]), r.pppropval[i]));
		return EXT_ERR_SUCCESS;
	} else if (PROPERTY_ROW_FLAG_FLAGGED == r.flag) {
		for (size_t i = 0; i < cols.count; ++i)
			TRY(p_flagged_pv(PROP_TYPE(cols.pproptag[i]),
			         *static_cast<FLAGGED_PROPVAL *>(r.pppropval[i])));
		return EXT_ERR_SUCCESS;
	}
	return EXT_ERR_BAD_SWITCH;
}

int EXT_PUSH::p_proprow(const LPROPTAG_ARRAY &cols, const PROPERTY_ROW &r)
{
	TRY(p_uint8(r.flag));
	if (r.flag == PROPERTY_ROW_FLAG_NONE) {
		for (size_t i = 0; i < cols.cvalues; ++i)
			TRY(p_propval(PROP_TYPE(cols.pproptag[i]), r.pppropval[i]));
		return EXT_ERR_SUCCESS;
	} else if (r.flag == PROPERTY_ROW_FLAG_FLAGGED) {
		for (size_t i = 0; i < cols.cvalues; ++i)
			TRY(p_flagged_pv(PROP_TYPE(cols.pproptag[i]),
			         *static_cast<FLAGGED_PROPVAL *>(r.pppropval[i])));
		return EXT_ERR_SUCCESS;
	}
	return EXT_ERR_BAD_SWITCH;
}

int EXT_PUSH::p_sortorder(const SORT_ORDER &r)
{
	if ((r.type & MVI_FLAG) == MV_FLAG)
		/* MV_FLAG set without MV_INSTANCE */
		return EXT_ERR_FORMAT;
	TRY(p_uint16(r.type));
	TRY(p_uint16(r.propid));
	return p_uint8(r.table_sort);
}

int EXT_PUSH::p_sortorder_set(const SORTORDER_SET &r)
{
	if (r.count == 0 || r.ccategories > r.count || r.cexpanded > r.ccategories)
		return EXT_ERR_FORMAT;
	TRY(p_uint16(r.count));
	TRY(p_uint16(r.ccategories));
	TRY(p_uint16(r.cexpanded));
	for (size_t i = 0; i < r.count; ++i)
		TRY(p_sortorder(r.psort[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_typed_str(const TYPED_STRING &r)
{
	TRY(p_uint8(r.string_type));
	switch (r.string_type) {
	case STRING_TYPE_NONE:
	case STRING_TYPE_EMPTY:
		return EXT_ERR_SUCCESS;
	case STRING_TYPE_STRING8:
	case STRING_TYPE_UNICODE_REDUCED:
		return p_str(r.pstring);
	case STRING_TYPE_UNICODE:
		return p_wstr(r.pstring);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int EXT_PUSH::p_recipient_row(const PROPTAG_ARRAY &pproptags, const RECIPIENT_ROW &r)
{
	BOOL b_unicode;
	PROPTAG_ARRAY proptags;
	
	b_unicode = FALSE;
	if (r.flags & RECIPIENT_ROW_FLAG_UNICODE)
		b_unicode = TRUE;
	TRY(p_uint16(r.flags));
	if (r.pprefix_used != nullptr)
		TRY(p_uint8(*r.pprefix_used));
	if (r.have_display_type)
		TRY(p_uint8(r.display_type));
	if (r.px500dn != nullptr)
		TRY(p_str(r.px500dn));
	if (r.pentry_id != nullptr)
		TRY(p_bin(*r.pentry_id));
	if (r.psearch_key != nullptr)
		TRY(p_bin(*r.psearch_key));
	if (r.paddress_type != nullptr)
		TRY(p_str(r.paddress_type));
	if (r.pmail_address != nullptr) {
		if (b_unicode)
			TRY(p_wstr(r.pmail_address));
		else
			TRY(p_str(r.pmail_address));
	}
	if (r.pdisplay_name != nullptr) {
		if (b_unicode)
			TRY(p_wstr(r.pdisplay_name));
		else
			TRY(p_str(r.pdisplay_name));
	}
	if (r.psimple_name != nullptr) {
		if (b_unicode)
			TRY(p_wstr(r.psimple_name));
		else
			TRY(p_str(r.psimple_name));
	}
	if (r.ptransmittable_name != nullptr) {
		if (b_unicode)
			TRY(p_wstr(r.ptransmittable_name));
		else
			TRY(p_str(r.ptransmittable_name));
	}
	TRY(p_uint16(r.count));
	if (r.count > pproptags.count)
		return EXT_ERR_FORMAT;
	proptags.count = r.count;
	proptags.pproptag = static_cast<uint32_t *>(pproptags.pproptag);
	return p_proprow(proptags, r.properties);
}

int EXT_PUSH::p_openrecipient_row(const PROPTAG_ARRAY &pproptags, const OPENRECIPIENT_ROW &r)
{
	TRY(p_uint8(r.recipient_type));
	TRY(p_uint16(r.cpid));
	TRY(p_uint16(r.reserved));
	uint32_t offset = m_offset;
	TRY(advance(sizeof(uint16_t)));
	TRY(p_recipient_row(pproptags, r.recipient_row));
	uint16_t row_size = m_offset - (offset + sizeof(uint16_t));
	uint32_t offset1 = m_offset;
	m_offset = offset;
	TRY(p_uint16(row_size));
	m_offset = offset1;
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_readrecipient_row(const PROPTAG_ARRAY &pproptags, const READRECIPIENT_ROW &r)
{
	TRY(p_uint32(r.row_id));
	TRY(p_uint8(r.recipient_type));
	TRY(p_uint16(r.cpid));
	TRY(p_uint16(r.reserved));
	uint32_t offset = m_offset;
	TRY(advance(sizeof(uint16_t)));
	TRY(p_recipient_row(pproptags, r.recipient_row));
	uint16_t row_size = m_offset - (offset + sizeof(uint16_t));
	uint32_t offset1 = m_offset;
	m_offset = offset;
	TRY(p_uint16(row_size));
	m_offset = offset1;
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_permission_data(const PERMISSION_DATA &r)
{
	TRY(p_uint8(r.flags));
	return p_tpropval_a(r.propvals);
}

int EXT_PUSH::p_rule_data(const RULE_DATA &r)
{
	TRY(p_uint8(r.flags));
	return p_tpropval_a(r.propvals);
}

int EXT_PUSH::p_abk_eid(const EMSAB_ENTRYID &r)
{
	TRY(p_uint32(r.flags));
	TRY(p_guid(muidEMSAB));
	TRY(p_uint32(r.version));
	TRY(p_uint32(r.type));
	return p_str(r.px500dn);
}

int EXT_PUSH::p_oneoff_eid(const ONEOFF_ENTRYID &r)
{
	TRY(p_uint32(r.flags));
	TRY(p_guid(muidOOP));
	TRY(p_uint16(r.version));
	TRY(p_uint16(r.ctrl_flags));
	if (r.ctrl_flags & CTRL_FLAG_UNICODE) {
		TRY(p_wstr(r.pdisplay_name));
		TRY(p_wstr(r.paddress_type));
		return p_wstr(r.pmail_address);
	} else {
		TRY(p_str(r.pdisplay_name));
		TRY(p_str(r.paddress_type));
		return p_str(r.pmail_address);
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
		return pext->p_bin(*r->pentry_id);
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

int EXT_PUSH::p_persistdata_a(const PERSISTDATA_ARRAY &r)
{
	PERSISTDATA last_data;
	
	for (size_t i = 0; i < r.count; ++i)
		TRY(ext_buffer_push_persistdata(this, r.ppitems[i]));
	last_data.persist_id = PERSIST_SENTINEL;
	last_data.element.element_id = ELEMENT_SENTINEL;
	last_data.element.pentry_id = NULL;
	return ext_buffer_push_persistdata(this, &last_data);
}

int EXT_PUSH::p_eid_a(const EID_ARRAY &r)
{
	TRY(p_uint32(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(p_uint64(r.pids[i]));
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_systime(const SYSTEMTIME &r)
{
	TRY(p_int16(r.year));
	TRY(p_int16(r.month));
	TRY(p_int16(r.dayofweek));
	TRY(p_int16(r.day));
	TRY(p_int16(r.hour));
	TRY(p_int16(r.minute));
	TRY(p_int16(r.second));
	return p_int16(r.milliseconds);
}

int EXT_PUSH::p_tzstruct(const TIMEZONESTRUCT &r)
{
	TRY(p_int32(r.bias));
	TRY(p_int32(r.standardbias));
	TRY(p_int32(r.daylightbias));
	TRY(p_int16(r.standardyear));
	TRY(p_systime(r.standarddate));
	TRY(p_int16(r.daylightyear));
	return p_systime(r.daylightdate);
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
	TRY(pext->p_systime(r->standarddate));
	return pext->p_systime(r->daylightdate);
}

int EXT_PUSH::p_tzdef(const TIMEZONEDEFINITION &r)
{
	uint16_t cbheader;
	char tmp_buff[262];
	
	TRY(p_uint8(r.major));
	TRY(p_uint8(r.minor));
	auto len = utf8_to_utf16le(r.keyname, tmp_buff, std::size(tmp_buff));
	if (len < 2)
		return EXT_ERR_CHARCNV;
	len -= 2;
	cbheader = 6 + len;
	TRY(p_uint16(cbheader));
	TRY(p_uint16(r.reserved));
	TRY(p_uint16(len / 2));
	TRY(p_bytes(tmp_buff, len));
	TRY(p_uint16(r.crules));
	for (size_t i = 0; i < r.crules; ++i)
		TRY(ext_buffer_push_tzrule(this, &r.prules[i]));
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
	if (r->overrideflags & ARO_SUBJECT) {
		tmp_len = strlen(r->subject);
		TRY(pext->p_uint16(tmp_len + 1));
		TRY(pext->p_uint16(tmp_len));
		TRY(pext->p_bytes(r->subject, tmp_len));
	}
	if (r->overrideflags & ARO_MEETINGTYPE)
		TRY(pext->p_uint32(r->meetingtype));
	if (r->overrideflags & ARO_REMINDERDELTA)
		TRY(pext->p_uint32(r->reminderdelta));
	if (r->overrideflags & ARO_REMINDER)
		TRY(pext->p_uint32(r->reminderset));
	if (r->overrideflags & ARO_LOCATION) {
		tmp_len = strlen(r->location);
		TRY(pext->p_uint16(tmp_len + 1));
		TRY(pext->p_uint16(tmp_len));
		TRY(pext->p_bytes(r->location, tmp_len));
	}
	if (r->overrideflags & ARO_BUSYSTATUS)
		TRY(pext->p_uint32(r->busystatus));
	if (r->overrideflags & ARO_ATTACHMENT)
		TRY(pext->p_uint32(r->attachment));
	if (r->overrideflags & ARO_SUBTYPE)
		TRY(pext->p_uint32(r->subtype));
	if (r->overrideflags & ARO_APPTCOLOR)
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
	if (writerversion2 >= 0x00003009)
		TRY(ext_buffer_push_changehighlight(pext, &r->changehighlight));
	TRY(pext->p_uint32(r->reservedblockee1size));
	if (r->reservedblockee1size != 0)
		TRY(pext->p_bytes(r->preservedblockee1, r->reservedblockee1size));
	if (overrideflags & (ARO_SUBJECT | ARO_LOCATION)) {
		TRY(pext->p_uint32(r->startdatetime));
		TRY(pext->p_uint32(r->enddatetime));
		TRY(pext->p_uint32(r->originalstartdate));
	}
	if (overrideflags & ARO_SUBJECT) {
		auto subj = r->subject != nullptr ? r->subject : "";
		auto tmp_len = strlen(subj) + 1;
		std::unique_ptr<char[]> pbuff;
		try {
			pbuff = std::make_unique<char[]>(2 * tmp_len);
		} catch (const std::bad_alloc &) {
			return EXT_ERR_ALLOC;
		}
		auto string_len = utf8_to_utf16le(subj, pbuff.get(), 2 * tmp_len);
		if (string_len < 2)
			return EXT_ERR_CHARCNV;
		if (string_len > UINT16_MAX)
			string_len = UINT16_MAX;
		string_len -= 2;
		TRY(pext->p_uint16(string_len / 2));
		TRY(pext->p_bytes(pbuff.get(), string_len));
	}
	if (overrideflags & ARO_LOCATION) {
		auto loc = r->location != nullptr ? r->location : "";
		auto tmp_len = strlen(loc) + 1;
		std::unique_ptr<char[]> pbuff;
		try {
			pbuff = std::make_unique<char[]>(2 * tmp_len);
		} catch (const std::bad_alloc &) {
			return EXT_ERR_ALLOC;
		}
		auto string_len = utf8_to_utf16le(loc, pbuff.get(), 2 * tmp_len);
		if (string_len < 2)
			return EXT_ERR_CHARCNV;
		if (string_len > UINT16_MAX)
			string_len = UINT16_MAX;
		string_len -= 2;
		TRY(pext->p_uint16(string_len / 2));
		TRY(pext->p_bytes(pbuff.get(), string_len));
	}
	if (overrideflags & (ARO_LOCATION | ARO_SUBJECT)) {
		TRY(pext->p_uint32(r->reservedblockee2size));
		if (r->reservedblockee2size != 0)
			TRY(pext->p_bytes(r->preservedblockee2, r->reservedblockee2size));
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_apptrecpat(const APPOINTMENT_RECUR_PAT &r)
{
	TRY(ext_buffer_push_recurrencepattern(this, &r.recur_pat));
	TRY(p_uint32(r.readerversion2));
	TRY(p_uint32(r.writerversion2));
	TRY(p_uint32(r.starttimeoffset));
	TRY(p_uint32(r.endtimeoffset));
	TRY(p_uint16(r.exceptioncount));
	for (size_t i = 0; i < r.exceptioncount; ++i)
		TRY(ext_buffer_push_exceptioninfo(this, &r.pexceptioninfo[i]));
	TRY(p_uint32(r.reservedblock1size));
	for (size_t i = 0; i < r.exceptioncount; ++i)
		TRY(ext_buffer_push_extendedexception(this, r.writerversion2, r.pexceptioninfo[i].overrideflags, &r.pextendedexception[i]));
	TRY(p_uint32(r.reservedblock2size));
	if (r.reservedblock2size == 0)
		return EXT_ERR_SUCCESS;
	return p_bytes(r.preservedblock2, r.reservedblock2size);
}

int EXT_PUSH::p_goid(const GLOBALOBJECTID &r)
{
	TRY(p_guid(r.arrayid));
	TRY(p_uint8(r.year >> 8));
	TRY(p_uint8(r.year & 0xFF));
	TRY(p_uint8(r.month));
	TRY(p_uint8(r.day));
	TRY(p_uint64(r.creationtime));
	TRY(p_bytes(r.x, 8));
	return p_bin_ex(r.data);
}


static int ext_buffer_push_attachment_list(
	EXT_PUSH *pext, const ATTACHMENT_LIST *r)
{
	int i;
	
	TRY(pext->p_uint16(r->count));
	for (i=0; i<r->count; i++) {
		TRY(pext->p_tpropval_a(r->pplist[i]->proplist));
		if (NULL != r->pplist[i]->pembedded) {
			TRY(pext->p_uint8(1));
			TRY(pext->p_msgctnt(*r->pplist[i]->pembedded));
		} else {
			TRY(pext->p_uint8(0));
		}
	}
	return EXT_ERR_SUCCESS;
}

int EXT_PUSH::p_msgctnt(const MESSAGE_CONTENT &r)
{
	TRY(p_tpropval_a(r.proplist));
	if (r.children.prcpts != nullptr) {
		TRY(p_uint8(1));
		TRY(p_tarray_set(*r.children.prcpts));
	} else {
		TRY(p_uint8(0));
	}
	if (r.children.pattachments != nullptr) {
		TRY(p_uint8(1));
		return ext_buffer_push_attachment_list(this, r.children.pattachments);
	} else {
		return p_uint8(0);
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

bool emsab_to_parts(EXT_PULL &ser, char *type, size_t tsize,
    char *addr, size_t asize)
{
	EMSAB_ENTRYID eid;
	if (ser.g_abk_eid(&eid) != EXT_ERR_SUCCESS || eid.type != DT_MAILUSER)
		return false;
	if (type != nullptr)
		gx_strlcpy(type, "EX", tsize);
	gx_strlcpy(addr, eid.px500dn, asize);
	return true;
}

bool emsab_to_email(EXT_PULL &ser, ESSDN_TO_USERNAME e2u,
    char *addr, size_t asize)
{
	EMSAB_ENTRYID eid;
	if (ser.g_abk_eid(&eid) != EXT_ERR_SUCCESS || eid.type != DT_MAILUSER)
		return false;
	return e2u(eid.px500dn, addr, asize);
}

bool oneoff_to_parts(EXT_PULL &ser, char *type, size_t tsize,
    char *addr, size_t asize)
{
	ONEOFF_ENTRYID eid;
	if (ser.g_oneoff_eid(&eid) != EXT_ERR_SUCCESS ||
	    strcasecmp(eid.paddress_type, "SMTP") != 0)
		return false;
	if (type != nullptr)
		gx_strlcpy(type, "SMTP", tsize);
	gx_strlcpy(addr, eid.pmail_address, asize);
	return true;
}
