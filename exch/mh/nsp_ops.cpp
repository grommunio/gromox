#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/scope.hpp>
#include "nsp_common.hpp"
#include "nsp_ops.hpp"
#define TRY(expr) do { int v = (expr); if (v != EXT_ERR_SUCCESS) return v; } while (false)
#define SCOPED_ABKFLAG(cls) \
	auto saved_flags_X1 = (cls).m_flags; \
	(cls).m_flags |= EXT_FLAG_ABK; \
	auto cl_flag_X1 = gromox::make_scope_exit([&]() { (cls).m_flags = saved_flags_X1; });
#define SCOPED_ABK_DISABLE(cls) \
	auto saved_flags_X2 = (cls).m_flags; \
	(cls).m_flags &= ~EXT_FLAG_ABK; \
	auto cl_flag_X2 = gromox::make_scope_exit([&]() { (cls).m_flags = saved_flags_X2; });

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
	SCOPED_ABKFLAG(*this);
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
		TRY(g_proptag_a(req.columns));
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
	SCOPED_ABKFLAG(*this);
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
		TRY(g_proptag_a(req.proptags));
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
		req.entryids.pbin = nullptr;
	} else {
		TRY(g_bin_a(&req.entryids));
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
	SCOPED_ABKFLAG(*this);
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
		TRY(g_proptag_a(req.proptags));
	}
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.values = nullptr;
	} else {
		req.values = anew<LTPROPVAL_ARRAY>();
		if (req.values == nullptr)
			return EXT_ERR_ALLOC;
		TRY(g_tpropval_a(req.values));
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
	SCOPED_ABKFLAG(*this);
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
		TRY(g_proptag_a(req.columns));
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
	SCOPED_ABKFLAG(*this);
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
		TRY(g_proptag_a(req.proptags));
	}
	TRY(g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		req.names = nullptr;
	} else {
		req.names = anew<STRING_ARRAY>();
		if (req.names == nullptr)
			return EXT_ERR_ALLOC;
		SCOPED_ABK_DISABLE(*this);
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
	SCOPED_ABKFLAG(*this);
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
		TRY(g_proptag_a(req.columns));
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
	TRY(ext.p_proptag_a(colrow->columns));
	TRY(ext.p_uint32(colrow->row_count));
	for (size_t i = 0; i < colrow->row_count; ++i)
		TRY(ext.p_proprow(colrow->columns, colrow->rows[i]));
	return EXT_ERR_SUCCESS;
}

int nsp_ext_push::p_nsp_response(const bind_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	TRY(p_guid(rsp.server_guid));
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
		TRY(p_proptag_a(*rsp.outmids));
	}
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const getmatches_response &rsp)
{
	SCOPED_ABKFLAG(*this);
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
		TRY(p_proptag_a(*rsp.mids));
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
	SCOPED_ABKFLAG(*this);
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	if (rsp.proptags == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(p_proptag_a(*rsp.proptags));
	}
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const getprops_response &rsp)
{
	SCOPED_ABKFLAG(*this);
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	TRY(p_uint32(rsp.codepage));
	if (rsp.row == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(p_tpropval_a(*rsp.row));
	}
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const getspecialtable_response &rsp)
{
	SCOPED_ABKFLAG(*this);
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
			TRY(p_tpropval_a(rsp.row[i]));
	}
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const gettemplateinfo_response &rsp)
{
	SCOPED_ABKFLAG(*this);
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	TRY(p_uint32(rsp.codepage));
	if (rsp.row == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(p_tpropval_a(*rsp.row));
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
	SCOPED_ABKFLAG(*this);
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
	SCOPED_ABKFLAG(*this);
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	if (rsp.columns == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(p_proptag_a(*rsp.columns));
	}
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const resolvenames_response &rsp)
{
	SCOPED_ABKFLAG(*this);
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	TRY(p_uint32(rsp.codepage));
	if (rsp.mids == nullptr) {
		TRY(p_uint8(0));
	} else {
		TRY(p_uint8(0xFF));
		TRY(p_proptag_a(*rsp.mids));
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
		TRY(p_proptag_a(*rsp.outmids));
	}
	return p_uint32(0);
}

int nsp_ext_push::p_nsp_response(const seekentries_response &rsp)
{
	SCOPED_ABKFLAG(*this);
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
