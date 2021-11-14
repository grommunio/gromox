#include <gromox/ext_buffer.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapi_types.hpp>
#include <gromox/scope.hpp>
#include "nsp_ops.hpp"
#define TRY(expr) do { int v = (expr); if (v != EXT_ERR_SUCCESS) return v; } while (false)
#define SCOPED_ABKFLAG(cls) \
	auto saved_flags = (cls).m_flags; \
	(cls).m_flags |= EXT_FLAG_ABK; \
	auto cl_flag = gromox::make_scope_exit([&]() { (cls).m_flags = saved_flags; });

static int nsp_ext_g_tpropval_a(nsp_ext_pull &ext, LTPROPVAL_ARRAY *proplist)
{
	SCOPED_ABKFLAG(ext);
	return ext.g_tpropval_a(proplist);
}

static int nsp_ext_g_proptag_a(nsp_ext_pull &ext, LPROPTAG_ARRAY *proptags)
{
	SCOPED_ABKFLAG(ext);
	return ext.g_proptag_a(proptags);
}

static int nsp_ext_g_stat(nsp_ext_pull &ext, STAT &s)
{
	TRY(ext.g_uint32(&s.sort_type));
	TRY(ext.g_uint32(&s.container_id));
	TRY(ext.g_uint32(&s.cur_rec));
	TRY(ext.g_int32(&s.delta));
	TRY(ext.g_uint32(&s.num_pos));
	TRY(ext.g_uint32(&s.total_rec));
	TRY(ext.g_uint32(&s.codepage));
	TRY(ext.g_uint32(&s.template_locale));
	return ext.g_uint32(&s.sort_locale);
}

static int nsp_ext_g_propname(nsp_ext_pull &ext, nsp_propname2 *propname)
{
	TRY(ext.g_guid(&propname->guid));
	return ext.g_uint32(&propname->id);
}

static int nsp_ext_g_entryid(nsp_ext_pull &ext, nsp_entryid *entryid)
{
	TRY(ext.g_uint8(&entryid->id_type));
	if (entryid->id_type != 0x87 && entryid->id_type != 0)
		return EXT_ERR_FORMAT;
	TRY(ext.g_uint8(&entryid->r1));
	TRY(ext.g_uint8(&entryid->r2));
	TRY(ext.g_uint8(&entryid->r3));
	TRY(ext.g_guid(&entryid->provider_uid));
	TRY(ext.g_uint32(&entryid->display_type));
	if (entryid->id_type == 0)
		return ext.g_str(&entryid->payload.dn);
	return ext.g_uint32(&entryid->payload.mid);
}

static int nsp_ext_g_entryids(nsp_ext_pull &ext, nsp_entryids *entryids)
{
	TRY(ext.g_uint32(&entryids->count));
	entryids->entryid = ext.anew<nsp_entryid>(entryids->count);
	if (entryids->entryid == nullptr) {
		entryids->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < entryids->count; ++i)
		TRY(nsp_ext_g_entryid(ext, &entryids->entryid[i]));
	return EXT_ERR_SUCCESS;
}

int nsp_ext_pull::g_nsp_request(bind_request &req)
{
	uint8_t tmp_byte;

	TRY(g_uint32(&req.flags));
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.stat = nullptr;
	} else {
		req.stat = anew<STAT>();
		if (req.stat == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_stat(*this, *req.stat));
	}
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int nsp_ext_pull::g_nsp_request(unbind_request &req)
{
	TRY(g_uint32(&req.reserved));
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int nsp_ext_pull::g_nsp_request(comparemids_request &req)
{
	uint8_t tmp_byte;

	TRY(g_uint32(&req.reserved));
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.stat = nullptr;
	} else {
		req.stat = anew<STAT>();
		if (req.stat == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_stat(*this, *req.stat));
	}
	TRY(g_uint32(&req.mid1));
	TRY(g_uint32(&req.mid2));
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int nsp_ext_pull::g_nsp_request(dntomid_request &req)
{
	uint8_t tmp_byte;

	TRY(g_uint32(&req.reserved));
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.names = nullptr;
	} else {
		req.names = anew<STRING_ARRAY>();
		if (req.names == nullptr)
			return EXT_ERR_ALLOC;
		TRY(g_str_a(req.names));
	}
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int nsp_ext_pull::g_nsp_request(getmatches_request &req)
{
	uint8_t tmp_byte;

	TRY(g_uint32(&req.reserved1));
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.stat = nullptr;
	} else {
		req.stat = anew<STAT>();
		if (req.stat == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_stat(*this, *req.stat));
	}
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.inmids = nullptr;
	} else {
		req.inmids = anew<MID_ARRAY>();
		if (req.inmids == nullptr)
			return EXT_ERR_ALLOC;
		TRY(g_proptag_a(req.inmids));
	}
	TRY(g_uint32(&req.reserved2));
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.filter = nullptr;
	} else {
		req.filter = anew<RESTRICTION>();
		if (req.filter == nullptr)
			return EXT_ERR_ALLOC;
		TRY(g_restriction(req.filter));
	}
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.propname = nullptr;
	} else {
		req.propname = anew<nsp_propname2>();
		if (req.propname == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_propname(*this, req.propname));
	}
	TRY(g_uint32(&req.row_count));
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.columns = nullptr;
	} else {
		req.columns = anew<LPROPTAG_ARRAY>();
		if (req.columns == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_proptag_a(*this, req.columns));
	}
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int nsp_ext_pull::g_nsp_request(getproplist_request &req)
{
	TRY(g_uint32(&req.flags));
	TRY(g_uint32(&req.mid));
	TRY(g_uint32(&req.codepage));
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int nsp_ext_pull::g_nsp_request(getprops_request &req)
{
	uint8_t tmp_byte;

	TRY(g_uint32(&req.flags));
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.stat = nullptr;
	} else {
		req.stat = anew<STAT>();
		if (req.stat == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_stat(*this, *req.stat));
	}
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.proptags = nullptr;
	} else {
		req.proptags = anew<LPROPTAG_ARRAY>();
		if (req.proptags == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_proptag_a(*this, req.proptags));
	}
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int nsp_ext_pull::g_nsp_request(getspecialtable_request &req)
{
	uint8_t tmp_byte;

	TRY(g_uint32(&req.flags));
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.stat = nullptr;
	} else {
		req.stat = anew<STAT>();
		if (req.stat == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_stat(*this, *req.stat));
	}
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.version = nullptr;
	} else {
		req.version = anew<uint32_t>();
		if (req.version == nullptr)
			return EXT_ERR_ALLOC;
		TRY(g_uint32(req.version));
	}
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int nsp_ext_pull::g_nsp_request(gettemplateinfo_request &req)
{
	uint8_t tmp_byte;

	TRY(g_uint32(&req.flags));
	TRY(g_uint32(&req.type));
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		req.dn = nullptr;
	else
		TRY(g_str(&req.dn));

	TRY(g_uint32(&req.codepage));
	TRY(g_uint32(&req.locale_id));
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int nsp_ext_pull::g_nsp_request(modlinkatt_request &req)
{
	uint8_t tmp_byte;

	TRY(g_uint32(&req.flags));
	TRY(g_uint32(&req.proptag));
	TRY(g_uint32(&req.mid));
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.entryids.count = 0;
		req.entryids.entryid = nullptr;
	} else {
		TRY(nsp_ext_g_entryids(*this, &req.entryids));
	}
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int nsp_ext_pull::g_nsp_request(modprops_request &req)
{
	uint8_t tmp_byte;

	TRY(g_uint32(&req.reserved));
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.stat = nullptr;
	} else {
		req.stat = anew<STAT>();
		if (req.stat == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_stat(*this, *req.stat));
	}
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.proptags = nullptr;
	} else {
		req.proptags = anew<LPROPTAG_ARRAY>();
		if (req.proptags == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_proptag_a(*this, req.proptags));
	}
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.values = nullptr;
	} else {
		req.values = anew<LTPROPVAL_ARRAY>();
		if (req.values == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_tpropval_a(*this, req.values));
	}
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int nsp_ext_pull::g_nsp_request(queryrows_request &req)
{
	uint8_t tmp_byte;

	TRY(g_uint32(&req.flags));
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.stat = nullptr;
	} else {
		req.stat = anew<STAT>();
		if (req.stat == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_stat(*this, *req.stat));
	}
	TRY(g_proptag_a(&req.explicit_table));
	TRY(g_uint32(&req.count));
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.columns = nullptr;
	} else {
		req.columns = anew<LPROPTAG_ARRAY>();
		if (req.columns == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_proptag_a(*this, req.columns));
	}
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int nsp_ext_pull::g_nsp_request(querycolumns_request &req)
{
	TRY(g_uint32(&req.reserved));
	TRY(g_uint32(&req.flags));
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int nsp_ext_pull::g_nsp_request(resolvenames_request &req)
{
	uint8_t tmp_byte;

	TRY(g_uint32(&req.reserved));
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.stat = nullptr;
	} else {
		req.stat = anew<STAT>();
		if (req.stat == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_stat(*this, *req.stat));
	}
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.proptags = nullptr;
	} else {
		req.proptags = anew<LPROPTAG_ARRAY>();
		if (req.proptags == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_proptag_a(*this, req.proptags));
	}
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.names = nullptr;
	} else {
		req.names = anew<STRING_ARRAY>();
		if (req.names == nullptr)
			return EXT_ERR_ALLOC;
		TRY(g_wstr_a(req.names));
	}
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int nsp_ext_pull::g_nsp_request(resortrestriction_request &req)
{
	uint8_t tmp_byte;

	TRY(g_uint32(&req.reserved));
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.stat = nullptr;
	} else {
		req.stat = anew<STAT>();
		if (req.stat == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_stat(*this, *req.stat));
	}
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.inmids = nullptr;
	} else {
		req.inmids = anew<MID_ARRAY>();
		if (req.inmids == nullptr)
			return EXT_ERR_ALLOC;
		TRY(g_proptag_a(req.inmids));
	}
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int nsp_ext_pull::g_nsp_request(seekentries_request &req)
{
	uint8_t tmp_byte;

	TRY(g_uint32(&req.reserved));
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.stat = nullptr;
	} else {
		req.stat = anew<STAT>();
		if (req.stat == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_stat(*this, *req.stat));
	}
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.target = nullptr;
	} else {
		req.target = anew<TAGGED_PROPVAL>();
		if (req.target == nullptr)
			return EXT_ERR_ALLOC;
		SCOPED_ABKFLAG(*this);
		TRY(g_tagged_pv(req.target));
	}
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.explicit_table = nullptr;
	} else {
		req.explicit_table = anew<MID_ARRAY>();
		if (req.explicit_table == nullptr)
			return EXT_ERR_ALLOC;
		TRY(g_proptag_a(req.explicit_table));
	}
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.columns = nullptr;
	} else {
		req.columns = anew<LPROPTAG_ARRAY>();
		if (req.columns == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_proptag_a(*this, req.columns));
	}
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int nsp_ext_pull::g_nsp_request(updatestat_request &req)
{
	uint8_t tmp_byte;

	TRY(g_uint32(&req.reserved));
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.stat = nullptr;
	} else {
		req.stat = anew<STAT>();
		if (req.stat == nullptr)
			return EXT_ERR_ALLOC;
		TRY(nsp_ext_g_stat(*this, *req.stat));
	}
	TRY(g_uint8(&req.delta_requested));
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int nsp_ext_pull::g_nsp_request(getmailboxurl_request &req)
{
	TRY(g_uint32(&req.flags));
	TRY(g_wstr(&req.user_dn));
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int nsp_ext_pull::g_nsp_request(getaddressbookurl_request &req)
{
	TRY(g_uint32(&req.flags));
	TRY(g_wstr(&req.user_dn));
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

static int nsp_ext_p_tpropval_a(nsp_ext_push &ext, const LTPROPVAL_ARRAY *proplist)
{
	SCOPED_ABKFLAG(ext);
	return ext.p_tpropval_a(proplist);
}

static int nsp_ext_p_proptag_a(nsp_ext_push &ext, const LPROPTAG_ARRAY *proptags)
{
	SCOPED_ABKFLAG(ext);
	return ext.p_proptag_a(proptags);
}

static int nsp_ext_p_stat(nsp_ext_push &ext, const STAT &s)
{
	TRY(ext.p_uint32(s.sort_type));
	TRY(ext.p_uint32(s.container_id));
	TRY(ext.p_uint32(s.cur_rec));
	TRY(ext.p_int32(s.delta));
	TRY(ext.p_uint32(s.num_pos));
	TRY(ext.p_uint32(s.total_rec));
	TRY(ext.p_uint32(s.codepage));
	TRY(ext.p_uint32(s.template_locale));
	return ext.p_uint32(s.sort_locale);
}

static int nsp_ext_p_colrow(nsp_ext_push &ext, const nsp_rowset2 *colrow)
{
	TRY(nsp_ext_p_proptag_a(ext, &colrow->columns));
	TRY(ext.p_uint32(colrow->row_count));
	SCOPED_ABKFLAG(ext);
	for (size_t i = 0; i < colrow->row_count; ++i)
		TRY(ext.p_proprow(&colrow->columns, &colrow->rows[i]));
	return EXT_ERR_SUCCESS;
}

int nsp_ext_push::p_nsp_response(const bind_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	TRY(p_guid(&rsp.server_guid));
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const unbind_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const comparemids_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	TRY(p_uint32(rsp.result1));
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const dntomid_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	if (rsp.outmids == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(p_proptag_a(rsp.outmids));
	}
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const getmatches_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	if (rsp.stat == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(nsp_ext_p_stat(*this, *rsp.stat));
	}
	if (rsp.mids == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(p_proptag_a(rsp.mids));
	}
	if (rsp.result != ecSuccess) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(nsp_ext_p_colrow(*this, &rsp.column_rows));
	}
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const getproplist_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	if (rsp.proptags == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(nsp_ext_p_proptag_a(*this, rsp.proptags));
	}
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const getprops_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	TRY(p_uint32(rsp.codepage));
	if (rsp.row == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(nsp_ext_p_tpropval_a(*this, rsp.row));
	}
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const getspecialtable_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	TRY(p_uint32(rsp.codepage));
	if (rsp.version == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(p_uint32(*rsp.version));
	}
	if (rsp.count == 0) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(p_uint32(rsp.count));
		for (size_t i = 0; i < rsp.count; ++i)
			TRY(nsp_ext_p_tpropval_a(*this, &rsp.row[i]));
	}
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const gettemplateinfo_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	TRY(p_uint32(rsp.codepage));
	if (rsp.row == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(nsp_ext_p_tpropval_a(*this, rsp.row));
	}
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const modlinkatt_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const modprops_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const queryrows_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	if (rsp.stat == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(nsp_ext_p_stat(*this, *rsp.stat));
	}
	if (rsp.result != ecSuccess) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(nsp_ext_p_colrow(*this, &rsp.column_rows));
	}
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const querycolumns_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	if (rsp.columns == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(nsp_ext_p_proptag_a(*this, rsp.columns));
	}
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const resolvenames_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	TRY(p_uint32(rsp.codepage));
	if (rsp.mids == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(p_proptag_a(rsp.mids));
	}
	if (rsp.result != ecSuccess) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(nsp_ext_p_colrow(*this, &rsp.column_rows));
	}
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const resortrestriction_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	if (rsp.stat == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(nsp_ext_p_stat(*this, *rsp.stat));
	}
	if (rsp.outmids == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(p_proptag_a(rsp.outmids));
	}
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const seekentries_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	if (rsp.stat == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(nsp_ext_p_stat(*this, *rsp.stat));
	}
	if (rsp.result != ecSuccess) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(nsp_ext_p_colrow(*this, &rsp.column_rows));
	}
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const updatestat_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	if (rsp.stat == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(nsp_ext_p_stat(*this, *rsp.stat));
	}
	if (rsp.delta == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(p_int32(*rsp.delta));
	}
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const getmailboxurl_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	TRY(p_wstr(rsp.server_url));
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const getaddressbookurl_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	TRY(p_wstr(rsp.server_url));
	return p_uint32(0);
}
